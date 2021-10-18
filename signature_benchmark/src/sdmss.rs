// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Shallow-Deep Merkle-tree Signature Scheme (SD-MSS) based on Winternitz OTS (WOTS+).

use std::convert::TryInto;

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::merkle::{MerkleSignature, UpdatableMerkleKeypair};

/// Security parameter, hash output size in bytes.
pub const N: usize = 128 / 8;

pub const S: usize = 2;
pub const D: usize = 7;
/// Client-side caching of deep tree (tree level, counting from root=0).
pub const C: usize = 7;

type SecKey = [u8; N];
type PubKey = [u8; (1 << S) * N + N];

/// SD-MSS-WOTS Keypair
// TODO save some space here
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Keypair {
    sk_seed: SecKey,
    pub shallow: UpdatableMerkleKeypair,
    pub deep: UpdatableMerkleKeypair,
}

/// SD-MSS-WOTS Signature
// TODO collapse `deep` and `new_deep_ctr` into one value to save 4 bytes?
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Signature {
    pub deep: bool,
    pub new_shallow_ctr: u32,
    pub new_deep_ctr: u32,
    pub merkle_sig: MerkleSignature,
}

impl Keypair {
    /// Generates a new SD-MSS-WOTS Keypair.
    /// Uses O(2^S + 2^D) memory.
    /// Has to calculate all 2^S + 2^D OTS keypairs.
    pub fn new() -> Self {
        let sk = Self::gensk(&mut OsRng);
        return Self::from_sk(sk);
    }

    /// Generate only a new random secret key.
    pub fn gensk(rng: &mut impl RngCore) -> SecKey {
        let mut sk = [0; N];
        rng.fill_bytes(&mut sk);
        return sk;
    }

    /// Generate keypair object containing public key and tree cache.
    pub fn from_sk(sk: SecKey) -> Self {
        let mut sha = Sha256::new();
        sha.update(sk);
        sha.update("shallow");
        let shallow_seed = sha.finalize()[..N].try_into().unwrap();

        let mut sha = Sha256::new();
        sha.update(sk);
        sha.update("deep");
        let deep_seed = sha.finalize()[..N].try_into().unwrap();

        Self {
            sk_seed: sk,
            shallow: UpdatableMerkleKeypair::from_sk(shallow_seed, S, S, true),
            deep: UpdatableMerkleKeypair::from_sk(deep_seed, D, C, false),
        }
    }

    /// Signs an input string, preferably using the shallow subtree.
    /// If shallow subtree was used up, deep subtree is used instead.
    /// Updates the subtrees if the remote counters allow for it.
    pub fn sign(
        &mut self,
        input: &str,
        remote_shallow_ctr: u32,
        remote_deep_ctr: u32,
    ) -> Signature {
        if remote_shallow_ctr == self.shallow.ctr_next {
            self.shallow.reconciliate();
        }

        if remote_deep_ctr == self.deep.ctr_next {
            self.deep.reconciliate();
        }

        let shallow_kps_used = self.shallow.ctr_next - self.shallow.ctr;
        if shallow_kps_used > (1 << (self.shallow.height)) {
            // signed too many messages with shallow tree
            unreachable!();
        } else if shallow_kps_used < (1 << (self.shallow.height)) {
            // not all signatures in shallow tree used yet -> use shallow tree
            let sig = self.shallow.sign(input);
            Signature {
                deep: false,
                new_shallow_ctr: self.shallow.ctr_next,
                new_deep_ctr: self.deep.ctr_next,
                merkle_sig: sig,
            }
        } else {
            // all signatures in shallow tree used -> use deep tree instead
            let sig = self.deep.sign(input);
            Signature {
                deep: true,
                new_shallow_ctr: self.shallow.ctr_next,
                new_deep_ctr: self.deep.ctr_next,
                merkle_sig: sig,
            }
        }
    }
}

impl Signature {
    /// Verifies the signature against the given public key (merkle tree root node).
    pub fn verify(&self, input: &str, shallow_pk: [u8; N], deep_pk: [u8; N]) -> bool {
        match self.deep {
            true => self.merkle_sig.verify(input, deep_pk),
            false => self.merkle_sig.verify(input, shallow_pk),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let mut merkle = Keypair::new();
        let dpk = merkle.deep.pk;

        let sig = merkle.sign("hello", 0, 0);
        assert_eq!(sig.verify("hello", merkle.shallow.cache[0], dpk), true);
        assert_eq!(sig.verify("world", merkle.shallow.cache[0], dpk), false);

        let sig = merkle.sign("world", 1, 0);
        assert_eq!(sig.verify("world", merkle.shallow.cache[0], dpk), true);
        assert_eq!(sig.verify("hello", merkle.shallow.cache[0], dpk), false);

        let sig = merkle.sign("", 2, 0);
        assert_eq!(sig.verify("", merkle.shallow.cache[0], dpk), true);
        assert_eq!(sig.verify(" ", merkle.shallow.cache[0], dpk), false);
    }

    #[test]
    fn all_wots_keys() {
        let mut merkle = Keypair::new();
        let spk = merkle.shallow.cache.clone();
        let dpk = merkle.deep.pk;

        // use up all keys in shallow subtree
        for i in 0..(1 << merkle.shallow.height) {
            let message = format!("hello {}", i);
            let sig = merkle.sign(&message, 0, 0);
            assert_eq!(sig.verify(&message, spk[i], dpk), true);
        }

        // use up all keys in deep subtree
        for i in 0..(1 << merkle.deep.height) {
            let message = format!("hello {}", i);
            let sig = merkle.sign(&message, 0, 0);
            assert_eq!(sig.verify(&message, spk[0], dpk), true);
        }
    }

    #[test]
    fn update() {
        let mut merkle = Keypair::new();
        let spk = merkle.shallow.cache.clone();
        let dpk = merkle.deep.pk;

        // use up all keys in shallow subtree
        for i in 0..(1 << merkle.shallow.height) {
            let message = format!("old {}", i);
            let sig = merkle.sign(&message, 0, 0);
            assert_eq!(sig.verify(&message, spk[i], dpk), true);
        }

        // use up all keys in deep subtree
        for i in 0..(1 << merkle.deep.height) {
            let message = format!("old {}", i);
            let sig = merkle.sign(&message, 0, 0);
            assert_eq!(sig.verify(&message, spk[0], dpk), true);
        }

        let ctr_s = merkle.shallow.ctr_next;
        let ctr_d = merkle.deep.ctr_next;

        // use up all keys in *new* shallow subtree
        for i in 0..(1 << merkle.shallow.height) {
            let message = format!("new {}", i);
            let sig = merkle.sign(&message, ctr_s, ctr_d);
            let spk = merkle.shallow.cache.clone();
            let dpk = merkle.deep.pk;
            assert_eq!(sig.verify(&message, spk[i], dpk), true);
        }

        // use up all keys in *new* deep subtree
        for i in 0..(1 << merkle.deep.height) {
            let message = format!("new {}", i);
            let sig = merkle.sign(&message, ctr_s, ctr_d);
            let spk = merkle.shallow.cache.clone();
            let dpk = merkle.deep.pk;
            assert_eq!(sig.verify(&message, spk[0], dpk), true);
        }
    }

    #[test]
    fn no_wots_keypair_reuse() {
        let mut merkle = Keypair::new();
        let mut shallow_indices = Vec::new();
        let mut deep_indices = Vec::new();
        let mut pkhs = Vec::new();

        // use up all keys in shallow subtree
        for _ in 0..(1 << merkle.shallow.height) {
            let sd_sig = merkle.sign("hello world", 0, 0);
            assert_eq!(sd_sig.deep, false);
            let sig = sd_sig.merkle_sig;
            assert_eq!(shallow_indices.iter().any(|&i| i == sig.index), false);
            assert_eq!(pkhs.iter().any(|&p| p == sig.wots_sig.pk_hash), false);
            shallow_indices.push(sig.index);
            pkhs.push(sig.wots_sig.pk_hash);
        }

        // use up all keys in deep subtree
        for _ in 0..(1 << merkle.deep.height) {
            let sd_sig = merkle.sign("hello world", 0, 0);
            assert_eq!(sd_sig.deep, true);
            let sig = sd_sig.merkle_sig;
            assert_eq!(deep_indices.iter().any(|&i| i == sig.index), false);
            assert_eq!(pkhs.iter().any(|&p| p == sig.wots_sig.pk_hash), false);
            deep_indices.push(sig.index);
            pkhs.push(sig.wots_sig.pk_hash);
        }
    }
}
