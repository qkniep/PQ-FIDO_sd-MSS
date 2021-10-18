// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Winternitz One-Time Signature (WOTS+) Scheme.
//! This implementation does not conform to RFC 8391 (see the paragraph below).
//!
//! Instead of simply hashing the message and signing that hash,
//! the public key hash is included in the message hash.
//! This allows for 50% shorter signatures with the same parameters.

use std::convert::TryInto;

use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The Winternitz Parameter, determining time-space tradeoff.
/// Needs to be a power of two, with 2 <= W <= 256.
pub const W: usize = 16;
pub const LOG2_W: usize = 4;

/// Security parameter, PRF output size in bytes.
/// Can be at most 256 / 8 (=32), as long as we instantiate with SHA256.
pub const N: usize = 128 / 8;

/// Message digest length in bytes.
const M: usize = N;

/// Length of the base `W` representation of a message of length `M`.
const L1: usize = (8 * M + LOG2_W - 1) / LOG2_W; // +LOG2_W-1 for ceil

/// Length of the base `W` checksum of a base `W` message of length `L1`.
/// `L2 = floor(log_W(L1 * (W - 1))) + 1`
const L2: usize = 3;
const L2_BYTES: usize = (L2 * LOG2_W + 7) / 8; // +7 for ceil

/// Total number of function chains, i.e. number of N-byte hashes in the actual signature.
const L: usize = L1 + L2;

/// WOTS+ Keypair
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Wots {
    pub pk_hash: [u8; N],
    pub pk_seed: [u8; N],
    sk_seed: [u8; N],
}

/// WOTS+ Signature
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct WotsSignature {
    pub pk_hash: [u8; N],
    pub pk_seed: [u8; N],
    pub signature: Vec<[u8; N]>,
}

impl Wots {
    /// Generates a new WOTS+ Keypair.
    pub fn new() -> Self {
        let mut seed = [0u8; N];
        thread_rng().fill_bytes(&mut seed);
        return Self::from_seed(seed);
    }

    /// Creates a WOTS+ Keypair from the specified seed.
    /// The seed needs to come from a high-entropy cryptographically secure source of randomness.
    pub fn from_seed(sk_seed: [u8; N]) -> Self {
        let mut sha = Sha256::new();

        // Generate public seed
        let pk_seed = prf(&sk_seed, L as u32);
        sha.update(pk_seed);

        // Calculate public key hash
        for i in 0..L {
            let secret = prf(&sk_seed, i as u32);
            let public = chain(&secret, W - 1, i, 0, &pk_seed);
            sha.update(public);
        }

        let pk_hash: [u8; N] = sha.finalize()[..N].try_into().unwrap();

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
            let cyc = c as usize;
            let secret = prf(&self.sk_seed, i as u32);
            signature.push(chain(&secret, cyc, i, 0, &self.pk_seed));
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
        let mut sha = Sha256::new();
        sha.update(self.pk_seed);
        for (i, &c) in cycles.iter().enumerate() {
            let cyc = c as usize;
            let sig = self.signature[i];
            sha.update(chain(&sig, W - 1 - cyc, i, cyc, &self.pk_seed));
        }
        let pk_hash: [u8; N] = sha.finalize()[..N].try_into().unwrap();

        return pk_hash.ct_eq(&self.pk_hash).unwrap_u8() == 1;
    }
}

/// Signs a single message, without needing a Wots object.
/// Generates secret values and bitmasks on-the-fly.
pub fn sign_once(msg: &str, sk_seed: &[u8; N], pk_hash: &[u8; N]) -> WotsSignature {
    let pk_seed = prf(sk_seed, L as u32);
    let cycles = cycles_for_msg(msg, pk_hash);

    // Calculate signature
    let mut signature: Vec<[u8; N]> = Vec::with_capacity(L);
    for (i, &c) in cycles.iter().enumerate() {
        let cyc = c as usize;
        let secret = prf(sk_seed, i as u32);
        signature.push(chain(&secret, cyc, i, 0, &pk_seed));
    }

    return WotsSignature {
        pk_hash: pk_hash.clone(),
        pk_seed: pk_seed,
        signature,
    };
}

/// Calculate the number of hash cycles applied to each base-w symbol, based on the given message.
pub fn cycles_for_msg(msg: &str, pk_hash: &[u8]) -> [u8; L] {
    let mut cycles = [0u8; L];

    // Hash input string together with public key hash
    let msg_hash = &Sha256::digest(msg.as_bytes())[..];
    let hash_bytes = &Sha256::digest(&[&pk_hash, msg_hash].concat())[..M];

    // Calculate message cycles
    cycles[0..L1].copy_from_slice(&base_w(hash_bytes, L1));

    // Calculate checksum
    let mut csum: u32 = cycles[..L1].iter().map(|&x| W as u32 - 1 - x as u32).sum();
    csum <<= 8 - ((L2 * LOG2_W) % 8);
    let csum_bytes = &csum.to_be_bytes()[4 - L2_BYTES..];
    cycles[L1..L].copy_from_slice(&base_w(csum_bytes, L2));

    return cycles;
}

/// Applies c cycles of the SHA-256/8N hash function to the input.
pub fn chain(input: &[u8; N], c: usize, chain: usize, start: usize, pk_seed: &[u8; N]) -> [u8; N] {
    let mut output = input.clone();

    for i in 0..c {
        let (key, bitmask) = prf2(&pk_seed, ((chain << 8) + (start + i)) as u32);
        for (i, byte) in bitmask.iter().enumerate() {
            output[i] ^= byte;
        }
        output = Sha256::digest(&[key, output].concat())[..N]
            .try_into()
            .unwrap();
    }

    return output;
}

/// Convert a byte slice into a sequence of characters of base W,
/// i.e. if W=16 returns a Vec twice the input length containing values in the range 0..=15.
pub fn base_w(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut b = bytes[bytes.len() - 1] as usize;
    let mut bi = bytes.len() - 1;
    let mut symbols = vec![0; len];
    let mut bits = 8;

    for i in (0..len).rev() {
        symbols[i] = (b % (1 << LOG2_W)) as u8;
        b /= 1 << LOG2_W;
        bits -= LOG2_W;
        if bits <= LOG2_W {
            bits += 8;
            if bi > 0 {
                bi -= 1;
                b += (bytes[bi as usize] as usize) << bits;
            }
        }
    }

    return symbols.to_vec();
}

/// SHA-256/8N-based PRF
/// Used for deriving the secret keys and the public seed from the secret seed.
pub fn prf(seed: &[u8; N], counter: u32) -> [u8; N] {
    let mut data = seed.clone();
    for (i, byte) in counter.to_be_bytes().iter().enumerate() {
        data[i] ^= byte;
    }
    return Sha256::digest(&data)[..N].try_into().unwrap();
}

/// SHA-256/8N-based PRF - with output length of 2N
/// Used for deriving the hash function keys and bitmasks from the public seed.
/// More efficient than two calls to prf(), at least for N <= 128 / 8.
pub fn prf2(seed: &[u8; N], counter: u32) -> ([u8; N], [u8; N]) {
    if N <= 128 / 8 {
        let mut data = seed.clone();
        for (i, byte) in counter.to_be_bytes().iter().enumerate() {
            data[i] ^= byte;
        }
        let output = Sha256::digest(&data);
        return (
            output[..N].try_into().unwrap(),
            output[N..].try_into().unwrap(),
        );
    } else {
        return (prf(seed, counter), prf(seed, !counter));
    }
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
        let mid = chain(&start, 3, 0, 0, &[0u8; N]);
        let end1 = chain(&mid, 7, 0, 3, &[0u8; N]);
        let end2 = chain(&start, 10, 0, 0, &[0u8; N]);
        let end3 = chain(&end2, 0, 0, 0, &[0u8; N]);
        assert_eq!(end1, end2);
        assert_eq!(end1, end3);
        assert_ne!(end1, start);
        assert_ne!(end1, mid);
        assert_ne!(start, mid);
    }

    #[test]
    fn base_w_conversion() {
        for t in 0..=255 {
            let bw = base_w(&[t], (8 + LOG2_W - 1) / LOG2_W);
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
