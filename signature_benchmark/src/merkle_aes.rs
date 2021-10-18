// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Merkle-Tree Signature Scheme using Winternitz One-Time Signatures (MSS-WOTS).

use std::convert::TryInto;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher};
use aes::Aes128;
use getrandom;

use crate::wots::{Wots, WotsSignature};

/// Tree Height
/// Allows signing of 2^H messages using the same public key.
/// Public key size increases linearly in H.
pub const H: usize = 7;

/// Cached tree layers, not counting root layer.
/// Allows for tradeoff between private key size and signing speed:
///   - private key size is rougly proportional to 2^C
///   - key generation requires at least 2^C memory to run
///   - time to sign a message is proportional to 2^(H-C)
pub const C: usize = 7;

/// Security parameter, hash output size in bytes.
pub const N: usize = 128 / 8;

/// MSS-WOTS Keypair
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Merkle {
    pub pk: [u8; N],
    next_seed: [u8; N],
    next_index: usize,
    tree_cache: Vec<[u8; N]>,
}

/// MSS-WOTS Signature
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct MerkleSignature {
    pub index: usize,
    pub wots_sig: WotsSignature,
    pub auth_path: Vec<[u8; N]>,
}

impl Merkle {
    /// Generates a new MSS-WOTS Keypair.
    /// Should use at most O(H) memory.
    pub fn new() -> Self {
        let mut tree = Vec::new();
        let mut tree_cache = Vec::new();
        let mut seed: [u8; N] = rand_digest().unwrap();

        for i in 0..(1 << H) {
            let secret = prng(&mut seed);
            let wots = Wots::from_seed(secret);
            tree.push(wots.pk_hash);
            tree_cache.push(wots.pk_hash);

            // Merge tree nodes
            let mut n = i + 1;
            while n % 2 == 0 {
                let a = tree.pop().unwrap();
                let b = tree.pop().unwrap();
                tree.push(hash2(&a, &b));
                n /= 2;
            }
        }

        assert_eq!(tree.len(), 1);

        return Self {
            pk: tree[0].clone(),
            next_seed: seed,
            next_index: 0,
            tree_cache,
        };
    }

    /// Signs an input string.
    /// Has to calculate 2^(H-C) OTS keypairs.
    // TODO make authentication path generation more efficient
    //      by caching top layers of Merkle-Tree
    // TODO allow lower caching levels, i.e. C < H
    pub fn sign(&self, input: &str) -> MerkleSignature {
        let wots = Wots::from_seed(self.next_seed);
        let sig = wots.sign(input);
        let mut auth_path = Vec::new();

        // Find authentication path in cache
        let mut offset = 0;
        for layer in (0..H).rev() {
            let i = offset + (self.next_index >> (H - layer)) ^ 1;
            auth_path.push(self.tree_cache[i]);
            offset += 1 << layer;
        }

        return MerkleSignature {
            index: self.next_index,
            wots_sig: sig,
            auth_path,
        };
    }
}

impl MerkleSignature {
    /// Verifies the signature against the given public key.
    pub fn verify(&self, input: &str, pk: [u8; N]) -> bool {
        if !self.wots_sig.verify(input) {
            return false;
        }

        let mut root = self.wots_sig.pk_hash;
        for (i, node) in self.auth_path.iter().enumerate() {
            if self.index & (1 << i) == 0 {
                root = hash2(&root, node)
            } else {
                root = hash2(node, &root)
            }
        }

        return root == pk;
    }
}

/// Get high-entropy randomness of the same length as the hash output from OS.
fn rand_digest() -> Result<[u8; N], getrandom::Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

/// AES-MMO Pseudo Random Number Generator
/// Returns a new random value and updates the seed in-place.
pub fn prng(seed: &mut [u8; N]) -> [u8; N] {
    let mut output = *GenericArray::from_slice(seed);

    let iv = GenericArray::from([0u8; N]);
    let cipher = Aes128::new(&iv);
    cipher.encrypt_block(&mut output);

    let s = u128::from_be_bytes(*seed);
    let o = u128::from_be_bytes(output.as_slice().try_into().expect("wrong length"));
    let r = s ^ o;
    let new_seed = r.wrapping_add(s).wrapping_add(1);
    *seed = new_seed.to_be_bytes();

    return r.to_be_bytes();
}

/// AES-MMO-based hash function
/// Hashes two blocks into one.
pub fn hash2(in1: &[u8; N], in2: &[u8; N]) -> [u8; N] {
    let mut block1 = *GenericArray::from_slice(in1);
    let mut block2 = *GenericArray::from_slice(in2);

    let iv = GenericArray::from([0u8; N]);
    let cipher = Aes128::new(&iv);
    cipher.encrypt_block(&mut block1);

    let s = u128::from_be_bytes(*in1);
    let o = u128::from_be_bytes(block1.as_slice().try_into().expect("wrong length"));
    let r = s ^ o;

    let cipher = Aes128::new(&GenericArray::from(r.to_be_bytes()));
    cipher.encrypt_block(&mut block2);
    let s = u128::from_be_bytes(block1.as_slice().try_into().expect("wrong length"));
    let o = u128::from_be_bytes(block2.as_slice().try_into().expect("wrong length"));
    let r = s ^ o;

    return r.to_be_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let merkle = Merkle::new();
        let sig = merkle.sign("hello world");
        assert_eq!(sig.verify("hello world", merkle.pk), true);
        assert_eq!(sig.verify("hello", merkle.pk), false);
    }
}
