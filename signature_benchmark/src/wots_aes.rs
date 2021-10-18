// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Winternitz One-Time Signature (W-OTS) Scheme.

use core::convert::TryInto;
use core::hash::Hasher;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher};
use aes::Aes128;
use getrandom;
use siphasher::sip128::{Hasher128, SipHasher};

// TODO implement checksum and W-OTS+
// TODO integrate public key into message hash, to remove collision-resistance requirement

/// The Winternitz Parameter, determining time-space tradeoff.
/// Should be 4 or 16.
/// Needs to be a power of two in the range 2..=256.
pub const W: usize = 256;

/// Number of symbols (to base W) in a single byte.
/// Needs to be such that: W ^ X == 256, i.e. X = log_W(256).
pub const X: usize = 1;

/// Security parameter, PRF output size in bytes.
pub const N: usize = 128 / 8;

/*/// Message digest length in bytes.
const M: usize = 512 / 8;

/// Length of the base `W` representation of a message of length `M`.
const L1: usize = 128;

/// Length of the base `W` checksum of a base `W` message of length `L1`.
const L2: usize = 3;

/// Number of function chains
const L: usize = L1 + L2;*/

/// W-OTS Keypair
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Wots {
    pub pk: [u8; N],
    sk: Vec<[u8; N]>,
}

/// W-OTS Signature
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct WotsSignature {
    pub pk: [u8; N],
    pub msg_hash: [u8; N],
    pub signature: Vec<[u8; N]>,
}

impl Wots {
    /// Generates a new W-OTS Keypair.
    pub fn new() -> Self {
        let seed: [u8; N] = rand_digest().unwrap();
        return Self::from_seed(seed);
    }

    /// Creates a W-OTS Keypair from the specified seed.
    pub fn from_seed(mut seed: [u8; N]) -> Self {
        let mut sk = Vec::<[u8; N]>::with_capacity(N * X);
        let mut pk = Vec::<[u8; N]>::with_capacity(N * X);

        for _ in 0..N * X {
            let secret = prng(&mut seed);
            sk.push(secret);
            let public = chain(&secret, W - 1);
            pk.push(public);
        }

        // TODO replace with AES-MMO hash
        let mut hasher = SipHasher::new();
        for p in &pk {
            hasher.write(p);
        }
        let h = hasher.finish128();
        let hash_bytes = h.as_bytes();

        return Self { pk: hash_bytes, sk };
    }

    /// Signs an input string.
    pub fn sign(&self, input: &str) -> WotsSignature {
        // Hash input
        // TODO replace with AES-MMO hash
        let mut hasher = SipHasher::new();
        hasher.write(input.as_bytes());
        let h = hasher.finish128();
        let hash_bytes = h.as_bytes();

        let mut signature: Vec<[u8; N]> = Vec::with_capacity(N * X);
        let mut sig_cycles: Vec<usize> = Vec::with_capacity(N * X);

        for i in 0..N {
            let symbols = base_w(hash_bytes[i]);

            for s in 0..X {
                sig_cycles.push(symbols[s] as usize);
                let index = i * X + s;
                let sig: [u8; N] = chain(&self.sk[index], sig_cycles[index]);
                signature.push(sig);
            }
        }

        return WotsSignature {
            pk: self.pk.clone(),
            msg_hash: hash_bytes.clone(),
            signature,
        };
    }
}

impl WotsSignature {
    /// Verifies the signature against the public key.
    pub fn verify(&self) -> bool {
        let mut i = 0;
        let mut pk = Vec::<[u8; N]>::with_capacity(N * X);

        for b in &self.msg_hash {
            for s in base_w(*b) {
                let cycles = W - 1 - (s as usize);
                pk.push(chain(&self.signature[i], cycles));
                i += 1;
            }
        }

        // TODO replace with AES-MMO hash
        let mut hasher = SipHasher::new();
        for p in &pk {
            hasher.write(p);
        }
        let h = hasher.finish128();
        let hash_bytes = h.as_bytes();
        assert_eq!(self.pk, hash_bytes);

        return true;
    }
}

/// Applies c cycles of the AES-MMO hash function to the input.
pub fn chain(input: &[u8; N], c: usize) -> [u8; N] {
    let mut output = *GenericArray::from_slice(input);

    let iv = GenericArray::from([0u8; N]);
    let cipher = Aes128::new(&iv);

    for _ in 0..c {
        let i = u128::from_be_bytes(output.as_slice().try_into().expect("wrong length"));
        cipher.encrypt_block(&mut output);
        let o = u128::from_be_bytes(output.as_slice().try_into().expect("wrong length"));
        let r = i ^ o;
        output = GenericArray::from(r.to_be_bytes());
    }

    return output.as_slice().try_into().expect("wrong length");
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

/// Get high-entropy randomness of the same length as the hash output from OS.
fn rand_digest() -> Result<[u8; N], getrandom::Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

/// AES-MMO-based PRNG
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_test() {
        let start = [0u8; N];
        let mid = chain(&start, 3);
        let end1 = chain(&mid, 7);
        let end2 = chain(&start, 10);
        assert_eq!(end1, end2);
    }

    #[test]
    fn sign_and_verify() {
        let wots = Wots::new();
        let sig = wots.sign("hello world");
        assert_eq!(sig.verify(), true);
    }
}
