// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Winternitz One-Time Signature (W-OTS+) Scheme.

use std::convert::TryInto;

use rand::{thread_rng, Rng, RngCore};

use super::sha256::Sha256;
use super::Hash256;

// TODO implement W-OTS+
// TODO integrate public key into message hash, to remove collision-resistance requirement

/// The Winternitz Parameter, determining time-space tradeoff.
/// Should be 4, 16 or 256.
pub const W: usize = 256;

/// Number of symbols (to base W) in a single byte.
/// Needs to be such that: W ^ X == 256, i.e. X = log_W(256).
pub const X: usize = 1;

/// Security parameter, PRF output size in bytes.
/// Can be at most 256 / 8 (=16), as long as we instantiate with SHA256.
pub const N: usize = 128 / 8;

/// Message digest length in bytes.
const M: usize = 128 / 8;

/// Length of the base `W` representation of a message of length `M`.
const L1: usize = M * X;

/// Length of the base `W` checksum of a base `W` message of length `L1`.
/// L2 = floor(log_W(L1 * (W - 1))) + 1
const L2: usize = 2;

/// Total number of function chains, i.e. number of N-byte hashes in signature.
const L: usize = L1 + L2;

/// Number of N-byte strings in private/public key.
const KL: usize = L + W - 1;

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
    pub msg_hash: [u8; M],
    pub signature: Vec<[u8; N]>,
}

impl Wots {
    /// Generates a new W-OTS Keypair.
    pub fn new() -> Self {
        let seed: [u8; N] = rand_seed();
        return Self::from_seed(seed);
    }

    /// Creates a W-OTS Keypair from the specified seed.
    pub fn from_seed(sk_seed: [u8; N]) -> Self {
        let mut seed = sk_seed.clone();
        let mut sk = Vec::<[u8; N]>::with_capacity(L);
        let mut pk = Vec::<[u8; N]>::with_capacity(KL);
        let mut bitmask = Vec::<[u8; N]>::with_capacity(W - 1);

        // Generate sk_1, ... , sk_L
        for _ in 0..L {
            let secret = prng(&mut seed);
            sk.push(secret);
            let public = chain(&secret, W - 1);
            pk.push(public);
        }

        // Generate PRF key
        let pk_seed = prng(&mut seed);
        //let prf_key = prng(&mut seed);

        // Generate r_1, ... , r_W-1
        for _ in 0..W - 1 {
            bitmask.push(prng(&mut seed));
        }

        let mut pk_hash = [0u8; N];
        pk_hash.copy_from_slice(&Sha256::hash(&pk.as_slice().concat())[..N]);

        return Self {
            pk_hash,
            pk_seed,
            sk_seed,
        };
    }

    /// Hashes and then signs an arbitrary input string.
    pub fn sign(&self, input: &str) -> WotsSignature {
        // Hash input string together with public key hash
        let msg_hash = &Sha256::hash(input.as_bytes())[..M];
        let mut sha = Sha256::new();
        sha.update(&self.pk_hash);
        sha.update(msg_hash);
        let hash_bytes = &sha.finalize()[..M];

        // Regenerate sk_1, ... sk_L.
        let mut sk = Vec::<[u8; N]>::with_capacity(L);
        let mut seed = self.sk_seed.clone();
        for _ in 0..L {
            let secret = prng(&mut seed);
            sk.push(secret);
        }

        // Calculate message signature
        let mut signature: Vec<[u8; N]> = Vec::with_capacity(L);
        for i in 0..M {
            let symbols = base_w(hash_bytes[i]);

            for s in 0..X {
                let cycles = symbols[s] as usize;
                let index = i * X + s;
                signature.push(chain(&sk[index], cycles));
            }
        }

        // Calculate and sign checksum
        // TODO make this work for X != 1
        let csum = hash_bytes
            .iter()
            .fold(0, |acc, &x| acc + W - 1 - x as usize);

        for i in 0..L2 {
            let mask = ((1 << (8 / X)) - 1) << ((8 / X) * i);
            let cycles = (csum & mask) >> ((8 / X) * i);
            signature.push(chain(&sk[L1 + i], cycles));
        }

        return WotsSignature {
            pk_hash: self.pk_hash.clone(),
            pk_seed: self.pk_seed.clone(),
            msg_hash: msg_hash.try_into().unwrap(),
            signature,
        };
    }
}

impl WotsSignature {
    /// Verifies the signature against the public key.
    pub fn verify(&self) -> bool {
        let mut i = 0;
        let mut pk = Vec::<[u8; N]>::with_capacity(L);

        // Hash input together with public key
        let mut sha = Sha256::new();
        sha.update(&self.pk_hash);
        sha.update(&self.msg_hash);
        let hash_bytes = &sha.finalize()[..M];

        for b in hash_bytes {
            for s in base_w(*b).iter() {
                let cycles = W - 1 - (*s as usize);
                pk.push(chain(&self.signature[i], cycles));
                i += 1;
            }
        }

        // checksum
        let csum = self
            .msg_hash
            .iter()
            .fold(0, |acc, &x| acc + W - 1 - x as usize);

        for i in 0..L2 {
            let mask = ((1 << (8 / X)) - 1) << ((8 / X) * i);
            let cycles = W - 1 - ((csum & mask) >> ((8 / X) * i));
            pk.push(chain(&self.signature[L1 + i], cycles));
        }

        let hash_bytes = &Sha256::hash(&pk.as_slice().concat())[..N];
        assert_eq!(self.pk_hash, hash_bytes);

        return true;
        // TODO: hash_bytes.ct_eq(self.pk).unwrap_u8() == 1;
    }
}

/// Applies c cycles of the SHA-256/8N hash function to the input.
pub fn chain(input: &[u8; N], c: usize) -> [u8; N] {
    let mut output = input.clone();

    for _ in 0..c {
        let tmp = &Sha256::hash(&output)[..N];
        output.copy_from_slice(tmp);
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

/// Get high-entropy randomness of the length required as seed from OS.
fn rand_seed() -> [u8; N] {
    let mut bytes = [0; N];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut bytes);
    return bytes;
}

/// SHA-256/8N-based PRNG
/// Returns a new random value and updates the seed in-place.
// TODO support N != 128 / 8 = 16
pub fn prng(seed: &mut [u8; N]) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(&Sha256::hash(&seed[..])[..N]);

    let s = u128::from_be_bytes(*seed);
    let o = u128::from_be_bytes(output[..].try_into().expect("wrong length"));
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
