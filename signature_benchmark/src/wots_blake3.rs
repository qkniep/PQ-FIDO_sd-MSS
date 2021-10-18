// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Winternitz One-Time Signature (W-OTS+) Scheme.
//! This implementation is based on RFC 8391 but does not comply.
//!
//! Instead of simply hashing the message and signing that hash,
//! the public key hash (PKH) is included in the message hash before signing.
//! This allows for 50% shorter signatures with the same parameters,
//! a message hash needs only have length N instead of 2N for security parameter N.

use std::convert::TryInto;

use rand::{thread_rng, RngCore};
use subtle::ConstantTimeEq;

/// The Winternitz Parameter, determining time-space tradeoff.
/// Signature size decreases logarithmically in W (linearly in LOG2_W).
/// Keygen/Sign time increases linearly in W (exponentially in LOG2_W).
/// Should be 4, 16 or 256.
pub const W: usize = 256;
pub const LOG2_W: usize = 8;

/// Number of symbols (in base W) in a single byte.
/// Needs to be such that: W ^ X == 256, i.e. X = log_W(256).
pub const X: usize = 1;

/// Security parameter, PRF output size in bytes.
/// Can be at most 256 / 8 (=32), as long as we instantiate with Blake3-256.
pub const N: usize = 256 / 8;

/// Message digest length in bytes.
const M: usize = 256 / 8;

/// Length of the base `W` representation of a message of length `M`.
const L1: usize = M * X;

/// Length of the base `W` checksum of a base `W` message of length `L1`.
/// `L2 = floor(log_W(L1 * (W - 1))) + 1`
const L2: usize = 2;

/// Total number of function chains, i.e. number of N-byte hashes in the actual signature.
const L: usize = L1 + L2;

/// W-OTS Keypair
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Wots {
    pub pk_hash: [u8; N],
    pub pk_seed: [u8; N],
    sk_seed: [u8; N],
}

/// W-OTS Signature
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct WotsSignature {
    pub pk_hash: [u8; N],
    pub pk_seed: [u8; N],
    pub signature: Vec<[u8; N]>,
}

impl Wots {
    /// Generates a new W-OTS Keypair.
    pub fn new() -> Self {
        let mut seed = [0u8; N];
        thread_rng().fill_bytes(&mut seed);
        return Self::from_seed(seed);
    }

    /// Creates a W-OTS Keypair from the specified seed.
    /// The seed needs to come from a high-entropy cryptographically secure source of randomness.
    pub fn from_seed(sk_seed: [u8; N]) -> Self {
        let mut pk_hash = [0u8; N];
        let mut hasher = blake3::Hasher::new();

        // Calculate public key hash
        for i in 0..L {
            let secret = prf(&sk_seed, i as u32);
            let public = chain(&secret, W - 1);
            hasher.update(&public);
        }

        // Generate public seed
        let pk_seed = prf(&sk_seed, L as u32);
        hasher.update(&pk_seed);
        pk_hash.copy_from_slice(&hasher.finalize().as_bytes()[..N]);

        return Self {
            pk_hash,
            pk_seed,
            sk_seed,
        };
    }

    /// Hashes and then signs an input string of arbitrary length.
    pub fn sign(&self, msg: &str) -> WotsSignature {
        let cycles = cycles_for_msg(msg, &self.pk_hash);

        // Calculate signature
        let mut signature: Vec<[u8; N]> = Vec::with_capacity(L);
        for (i, &c) in cycles.iter().enumerate() {
            let secret = prf(&self.sk_seed, i as u32);
            signature.push(chain(&secret, c as usize));
        }

        return WotsSignature {
            pk_hash: self.pk_hash.clone(),
            pk_seed: self.pk_seed.clone(),
            signature,
        };
    }
}

impl WotsSignature {
    /// Verifies the signature against the public key.
    pub fn verify(&self, msg: &str) -> bool {
        let cycles = cycles_for_msg(msg, &self.pk_hash);

        // Calculate public key hash
        let mut hasher = blake3::Hasher::new();
        for (i, &c) in cycles.iter().enumerate() {
            let sig = self.signature[i];
            hasher.update(&chain(&sig, W - 1 - c as usize));
        }
        hasher.update(&self.pk_seed);
        let pk_hash: [u8; N] = hasher.finalize().as_bytes()[..N].try_into().unwrap();

        return pk_hash.ct_eq(&self.pk_hash).unwrap_u8() == 1;
    }
}

pub fn cycles_for_msg(msg: &str, pk_hash: &[u8]) -> [u8; L] {
    let mut cycles = [0u8; L];

    // Hash input string together with public key hash
    let msg_hash = blake3::hash(msg.as_bytes());
    let msg_hash_bytes = &msg_hash.as_bytes()[..];
    let hash = blake3::hash(&[&pk_hash, msg_hash_bytes].concat());
    let hash_bytes = &hash.as_bytes()[..M];

    // Calculate message signature
    for i in 0..M {
        cycles[i * X..(i + 1) * X].copy_from_slice(&base_w(hash_bytes[i]));
    }

    // Calculate checksum
    let mut csum: u32 = cycles[..L1].iter().map(|&x| W as u32 - 1 - x as u32).sum();
    csum <<= 8 - ((L2 * LOG2_W) % 8);
    let csum_bytes = &csum.to_be_bytes()[4 - L2..];
    for i in 0..L2 {
        cycles[(L1 + i) * X..(L1 + i + 1) * X].copy_from_slice(&base_w(csum_bytes[i]));
    }

    return cycles;
}

/// Applies c cycles of the Blake3-256/8N hash function to the input.
pub fn chain(input: &[u8; N], c: usize) -> [u8; N] {
    let mut output = input.clone();

    for _ in 0..c {
        output = blake3::hash(&output).as_bytes()[..N].try_into().unwrap();
    }

    return output;
}

/// Convert a single byte into a sequence of character of base W,
/// i.e. if W=16 returns 2 values in the range 0..=15.
pub fn base_w(byte: u8) -> [u8; X] {
    let mut b = byte as usize;
    let mut symbols = [0u8; X];

    for s in 0..X {
        symbols[X - 1 - s] = (b % W) as u8;
        b /= W;
    }

    return symbols;
}

/// Blake3-256/8N-based PRF
pub fn prf(seed: &[u8; N], counter: u32) -> [u8; N] {
    // convert counter to bytes
    let mut counter_bytes = [0u8; N];
    counter_bytes[N - 4..].copy_from_slice(&counter.to_be_bytes());

    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&counter_bytes);
    return hasher.finalize().as_bytes()[..N].try_into().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let wots = Wots::new();
        let sig = wots.sign("hello world");
        assert_eq!(sig.verify("hello world"), true);
        assert_eq!(sig.verify("hello"), false);
        assert_eq!(sig.verify("hello world 123"), false);
        assert_eq!(sig.verify("123 hello world"), false);
    }

    #[test]
    fn hash_chain_test() {
        let start = [0u8; N];
        let mid = chain(&start, 3);
        let end1 = chain(&mid, 7);
        let end2 = chain(&start, 10);
        let end3 = chain(&end2, 0);
        assert_eq!(end1, end2);
        assert_eq!(end1, end3);
        assert_ne!(end1, start);
        assert_ne!(end1, mid);
        assert_ne!(start, mid);
    }

    #[test]
    fn base_w_conversion() {
        for t in 0..=255 {
            let bw = base_w(t);
            let mut sum = 0usize;
            let mut value = 1usize;
            for digit in bw.iter().rev() {
                sum += (*digit as usize) * value;
                value *= W;
            }
            assert_eq!(sum, t as usize);
        }
    }
}
