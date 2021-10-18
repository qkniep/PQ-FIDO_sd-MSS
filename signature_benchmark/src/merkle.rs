// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Merkle-Tree Signature Scheme using Winternitz One-Time Signatures (MSS-WOTS).
//! This implements an updatable Merkle-Tree, i.e. ...

use std::convert::TryInto;

use getrandom;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::wots::{self, Wots, WotsSignature};

/// Security parameter, hash output size in bytes.
pub const N: usize = 128 / 8;

/// MSS-WOTS+ Keypair
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct UpdatableMerkleKeypair {
    /// Tree Height (without root layer)
    ///   - can sign 2^height messages using the same public key
    ///   - signature size increases linearly in height
    ///   - key generation and signature times grow exponentially in height.
    pub height: usize,
    pub caching: usize,

    pub pk: [u8; N],
    pub pk_next: [u8; N],
    sk_seed: [u8; N],
    pub ctr: u32,
    pub ctr_next: u32,
    pub cache: Vec<[u8; N]>,
    cache_next: Vec<[u8; N]>,

    /// Enables server-side caching mode, where the cached nodes are used as PK.
    pub server_side_caching: bool,
}

/// MSS-WOTS+ Signature
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct MerkleSignature {
    pub index: u32,
    pub wots_sig: WotsSignature,
    pub auth_path: Vec<[u8; N]>,
}

impl UpdatableMerkleKeypair {
    /// Generates a new MSS-WOTS+ Keypair.
    /// Uses O(2^h) memory and has to calculate all 2^h OTS keypairs and all intermediate nodes.
    pub fn new(h: usize, c: usize, ssc: bool) -> Self {
        let seed: [u8; N] = rand_digest().unwrap();
        return Self::from_sk(seed, h, c, ssc);
    }

    pub fn from_sk(seed: [u8; N], h: usize, c: usize, ssc: bool) -> Self {
        // Calculate leaf nodes
        let mut leaves = Vec::with_capacity(1 << h);
        for i in 0usize..(1 << h) {
            leaves.push(calculate_leaf(&seed, i as u32));
        }

        let (root, cache) = calculate_root_and_cache(leaves, c);

        return Self {
            height: h,
            caching: c,
            pk: root.clone(),
            pk_next: root.clone(),
            sk_seed: seed,
            ctr: 0,
            ctr_next: 0,
            cache: cache.clone(),
            cache_next: cache,
            server_side_caching: ssc,
        };
    }

    /// Signs an input string.
    /// Has to calculate 2^(H-C) OTS keypairs.
    pub fn sign(&mut self, input: &str) -> MerkleSignature {
        // Get WOTS+ public key hash from cache or calculate it now
        let pkh = if self.caching == self.height {
            self.cache[self.ctr_next as usize - self.ctr as usize]
        } else {
            calculate_leaf(&self.sk_seed, self.ctr_next)
        };

        // Create WOTS+ signature
        let mut index_bytes = [0u8; N];
        index_bytes[..4].copy_from_slice(&self.ctr_next.to_be_bytes());
        let seed = hash2(&self.sk_seed, &index_bytes);
        let sig = wots::sign_once(input, &seed, &pkh);

        // Calculate Merkle authentication path
        let auth_path = if self.server_side_caching {
            Vec::new()
        } else {
            self.auth_path(self.ctr_next - self.ctr)
        };

        // Finish signature
        let sig = MerkleSignature {
            index: self.ctr_next - self.ctr,
            wots_sig: sig,
            auth_path,
        };

        self.ctr_next += 1;
        self.update();

        return sig;
    }

    /// Add a new WOTS+ public key hash to the 'new' part of the Merkle-Tree.
    pub fn update(&mut self) {
        if self.caching == self.height {
            let index = self.ctr_next + (1 << self.height) - 1;
            let pkh = calculate_leaf(&self.sk_seed, index as u32);
            self.cache_next = self.cache_next[1..].to_vec();
            self.cache_next.push(pkh);
        }

        // get leaves from cache or calculate them now
        let leaves = if self.caching == self.height {
            self.cache_next.clone()
        } else {
            let mut leaves = Vec::new();
            for l in self.ctr_next..self.ctr_next + (1 << self.height) {
                leaves.push(calculate_leaf(&self.sk_seed, l));
            }
            leaves
        };

        let (root, cache) = calculate_root_and_cache(leaves, self.caching);
        if self.caching != self.height {
            self.cache_next = cache;
        }
        self.pk_next = root;
    }

    /// Make the 'new' part the new full Merkle-Tree, trimming no longer needed leaf nodes.
    pub fn reconciliate(&mut self) {
        self.cache = self.cache_next.clone();
        self.ctr = self.ctr_next;
        self.pk = self.pk_next;
    }

    fn auth_path(&self, index: u32) -> Vec<[u8; N]> {
        let mut auth_path = Vec::new();
        for i in 0..self.height {
            let leaves = if i >= self.height - self.caching {
                let i2 = i - (self.height - self.caching);
                let index2 = index >> (i - i2);
                let start = (index2 - index2 % (1 << i2)) ^ (1 << i2);
                let end = start + (1 << i2);
                self.cache[start as usize..end as usize].to_vec()
            } else {
                let start = (index - index % (1 << i)) ^ (1 << i);
                let end = start + (1 << i);
                let mut leaves = Vec::new();
                for l in start..end {
                    leaves.push(calculate_leaf(&self.sk_seed, self.ctr + l));
                }
                leaves
            };

            let (root, _) = calculate_root_and_cache(leaves, self.caching);
            auth_path.push(root);
        }
        auth_path
    }
}

impl MerkleSignature {
    /// Verifies the signature against the given public key (merkle tree root node).
    pub fn verify(&self, input: &str, pk: [u8; N]) -> bool {
        // Verify WOTS+ signature
        if !self.wots_sig.verify(input) {
            return false;
        }

        // Verify authentication path
        let mut root = self.wots_sig.pk_hash;
        for (i, node) in self.auth_path.iter().enumerate() {
            root = match self.index & (1 << i) {
                0 => hash2(&root, node),
                _ => hash2(node, &root),
            };
        }
        return root.ct_eq(&pk).unwrap_u8() == 1;
    }
}

fn calculate_leaf(seed: &[u8; N], index: u32) -> [u8; N] {
    let mut index_bytes = [0u8; N];
    index_bytes[..4].copy_from_slice(&index.to_be_bytes());

    let secret = hash2(seed, &index_bytes);
    let wots = Wots::from_seed(secret);
    wots.pk_hash
}

/// Gets N bytes of high-entropy randomness from the OS.
fn rand_digest() -> Result<[u8; N], getrandom::Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

/// Calculates the root hash of a given (sub-)tree.
/// Panics if given a number of leaves that is not a power of two.
fn calculate_root_and_cache(leaves: Vec<[u8; N]>, caching: usize) -> ([u8; N], Vec<[u8; N]>) {
    if leaves.len().count_ones() != 1 {
        panic!("invalid number of leaves: needs to be a power of two");
    }

    let mut tmp = leaves.to_vec();
    let mut cache = Vec::new();

    while tmp.len() > 1 {
        if tmp.len() == 1 << caching {
            cache = tmp.clone();
        }
        tmp = tmp.chunks(2).fold(Vec::new(), |mut vec, chunk| {
            vec.push(hash2(&chunk[0], &chunk[1]));
            vec
        });
    }

    return (tmp[0], cache);
}

/// Hashes two N-byte blocks into one.
pub fn hash2(in1: &[u8; N], in2: &[u8; N]) -> [u8; N] {
    Sha256::digest(&[&in1[..], &in2[..]].concat())[..N]
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let mut merkle = UpdatableMerkleKeypair::new(7, 7, false);
        let sig = merkle.sign("hello");
        assert_eq!(sig.verify("hello", merkle.pk), true);
        assert_eq!(sig.verify("world", merkle.pk), false);

        let sig = merkle.sign("world");
        assert_eq!(sig.verify("world", merkle.pk), true);
        assert_eq!(sig.verify("hello", merkle.pk), false);

        let sig = merkle.sign("");
        assert_eq!(sig.verify("", merkle.pk), true);
        assert_eq!(sig.verify(" ", merkle.pk), false);
    }

    #[test]
    fn all_wots_keys() {
        let mut merkle = UpdatableMerkleKeypair::new(7, 7, false);
        for _ in 0..(1 << merkle.height) {
            let sig = merkle.sign("hello");
            assert_eq!(sig.verify("hello", merkle.pk), true);
        }
    }

    #[test]
    fn server_side_caching() {
        let mut merkle = UpdatableMerkleKeypair::new(3, 3, true);
        for i in 0..(1 << merkle.height) {
            let sig = merkle.sign("hello");
            assert_eq!(sig.verify("hello", merkle.cache[i]), true);
        }
    }

    #[test]
    fn no_wots_keypair_reuse() {
        let mut merkle = UpdatableMerkleKeypair::new(7, 7, false);
        let mut indices = Vec::new();
        let mut pkhs = Vec::new();

        for _ in 0..(1 << merkle.height) {
            let sig = merkle.sign("hello world");
            assert_eq!(indices.iter().any(|&i| i == sig.index), false);
            assert_eq!(pkhs.iter().any(|&p| p == sig.wots_sig.pk_hash), false);
            indices.push(sig.index);
            pkhs.push(sig.wots_sig.pk_hash);
        }
    }

    #[test]
    fn update_and_reconciliate() {
        let mut merkle = UpdatableMerkleKeypair::new(7, 7, false);
        let sig1 = merkle.sign("hello");
        assert_eq!(sig1.verify("hello", merkle.pk), true);
        let sig2 = merkle.sign("world");
        assert_eq!(sig2.verify("world", merkle.pk), true);

        // check that old signatures become invalid under new pk root
        merkle.reconciliate();
        assert_eq!(sig1.verify("hello", merkle.pk), false);
        assert_eq!(sig2.verify("world", merkle.pk), false);

        // check that cache shifts as expected
        let pkh = calculate_leaf(&merkle.sk_seed, 2);
        assert_eq!(merkle.cache[0], pkh);

        // ...but new signatures are valid again
        let sig1 = merkle.sign("hello");
        let sig2 = merkle.sign("world");
        assert_eq!(sig1.verify("hello", merkle.pk), true);
        assert_eq!(sig2.verify("world", merkle.pk), true);
    }

    #[test]
    fn full_update() {
        let mut merkle = UpdatableMerkleKeypair::new(2, 2, false);

        for _ in 0..(1 << merkle.height) {
            let sig = merkle.sign("hello");
            assert_eq!(sig.verify("hello", merkle.pk), true);
        }

        merkle.reconciliate();

        let sig = merkle.sign("hello");
        assert_eq!(sig.verify("hello", merkle.pk), true);
    }

    #[test]
    fn merkle_root_calculation() {
        let leaves = [[42; N], [31; N], [93; N], [57; N]];

        let (inner1, _) = calculate_root_and_cache(leaves[..2].to_vec(), 0);
        assert_eq!(inner1, hash2(&[42; N], &[31; N]));

        let (inner2, _) = calculate_root_and_cache(leaves[2..].to_vec(), 0);
        assert_eq!(inner2, hash2(&[93; N], &[57; N]));

        let (root, _) = calculate_root_and_cache(leaves.to_vec(), 0);
        assert_eq!(root, hash2(&inner1, &inner2));
    }

    /*
    #[test]
    fn auth_path_calculation() {
        let leaves = [[42; N], [31; N], [93; N], [57; N]];

        let auth_path = calculate_auth_path(&leaves, 1, 2);
        assert_eq!(auth_path.len(), 2);
        assert_eq!(auth_path[0], leaves[0]);
        assert_eq!(auth_path[1], hash2(&[93; N], &[57; N]));

        let inner = hash2(&auth_path[0], &leaves[1]);
        assert_eq!(inner, calculate_root(&leaves[..2]));

        let root = hash2(&inner, &auth_path[1]);
        assert_eq!(root, calculate_root(&leaves));
    }
    */
}
