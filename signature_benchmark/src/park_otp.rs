// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Park One-Time Password scheme

use std::convert::TryInto;

use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Security Parameter
const N: usize = 32;

pub struct Proofer {
    seed: [u8; N],
    last_ch: i32,
    current_x: [u8; N],
    next_x: [u8; N],
}

pub struct Verifier {
    last_ch: i32,
    last_y: [u8; N],
    last_z: [u8; N],
}

impl Proofer {
    pub fn new() -> Self {
        let mut seed = [0u8; N];
        thread_rng().fill_bytes(&mut seed);
        let mut p = Self {
            seed,
            last_ch: 0,
            current_x: [0u8; N],
            next_x: [0u8; N],
        };
        p.current_x = p.derive_x(1);
        p.next_x = p.derive_x(2);
        return p;
    }

    pub fn pk(&self) -> ([u8; N], [u8; N]) {
        assert_eq!(self.last_ch, 0);
        let y0 = hash_n_times(self.current_x, 1);
        let y1 = hash_n_times(self.next_x, 1);
        let z0 = calculate_z(self.current_x, y1);
        return (y0, z0);
    }

    pub fn reply(&mut self, ch: i32) -> ([u8; N], [u8; N], [u8; N]) {
        self.last_ch = ch;
        let x = self.current_x.clone();
        let y = hash_n_times(self.next_x.clone(), 1);

        // move further in the chain
        self.current_x = self.next_x;
        self.next_x = self.derive_x(self.last_ch + 2);

        let next_y = hash_n_times(self.next_x, 1);
        let z = calculate_z(self.current_x, next_y);

        return (x, y, z);
    }

    fn derive_x(&self, i: i32) -> [u8; N] {
        let mut sha = Sha256::new();
        // TODO: sha.update(<some kind of proofer ID>);
        sha.update(self.seed);
        sha.update(i.to_be_bytes());
        let double_hash = Sha256::digest(&sha.finalize());
        return double_hash.try_into().unwrap();
    }
}

impl Verifier {
    pub fn new((y, z): ([u8; N], [u8; N])) -> Self {
        Self {
            last_ch: 0,
            last_y: y,
            last_z: z,
        }
    }

    pub fn next_challenge(&mut self) -> i32 {
        self.last_ch += 1;
        self.last_ch
    }

    pub fn verify(&mut self, (x, y, z): ([u8; N], [u8; N], [u8; N])) -> bool {
        if Sha256::digest(&x).ct_eq(&self.last_y).unwrap_u8() == 0 {
            return false;
        }
        let z_check = calculate_z(x, y);
        if z_check.ct_eq(&self.last_z).unwrap_u8() == 0 {
            return false;
        }
        self.last_y = y;
        self.last_z = z;
        return true;
    }
}

fn hash_n_times(input: [u8; N], n: i32) -> [u8; N] {
    let mut output = input.clone();
    for _ in 0..n {
        let tmp = &Sha256::digest(&output);
        output.copy_from_slice(tmp);
    }
    output
}

fn calculate_z(x: [u8; N], y: [u8; N]) -> [u8; N] {
    let mut sha = Sha256::new();
    sha.update(x);
    sha.update(y);
    return sha.finalize().try_into().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut p = Proofer::new();
        let mut v = Verifier::new(p.pk());

        let ch = v.next_challenge();
        let pwd = p.reply(ch);
        assert_eq!(v.verify(pwd), true);
    }

    #[test]
    fn long_chain() {
        let mut p = Proofer::new();
        let mut v = Verifier::new(p.pk());

        for _ in 0..10_000 {
            let ch = v.next_challenge();
            let pwd = p.reply(ch);
            assert_eq!(v.verify(pwd), true);
        }
    }
}
