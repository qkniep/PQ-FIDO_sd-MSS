// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Lamport One-Time Password scheme

use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Security Parameter
const N: usize = 32;

pub struct Proofer {
    n: i32,
    last_ch: i32,
    secret: [u8; N],
}

pub struct Verifier {
    last_ch: i32,
    last_otp: [u8; N],
}

impl Proofer {
    pub fn new(n: i32) -> Self {
        let mut secret = [0u8; N];
        thread_rng().fill_bytes(&mut secret);
        Self {
            n,
            last_ch: n,
            secret,
        }
    }

    pub fn pk(&self) -> [u8; N] {
        hash_x_times(self.secret.clone(), self.n)
    }

    pub fn reply(&mut self, ch: i32) -> [u8; N] {
        self.last_ch = ch;
        hash_x_times(self.secret.clone(), ch)
    }
}

impl Verifier {
    pub fn new(n: i32, pk: [u8; N]) -> Self {
        Self {
            last_ch: n,
            last_otp: pk,
        }
    }

    pub fn next_challenge(&mut self) -> i32 {
        self.last_ch -= 1;
        self.last_ch
    }

    pub fn verify(&mut self, otp: [u8; N]) -> bool {
        let hash = Sha256::digest(&otp);
        if hash.ct_eq(&self.last_otp).unwrap_u8() == 0 {
            return false;
        }
        self.last_otp = otp;
        return true;
    }
}

fn hash_x_times(input: [u8; N], x: i32) -> [u8; N] {
    let mut output = input.clone();
    for _ in 0..x {
        let tmp = &Sha256::digest(&output);
        output.copy_from_slice(tmp);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut p = Proofer::new(10);
        let mut v = Verifier::new(p.n, p.pk());

        let ch = v.next_challenge();
        let pwd = p.reply(ch);
        assert_eq!(v.verify(pwd), true);
    }

    #[test]
    fn full_chain() {
        let mut p = Proofer::new(10);
        let mut v = Verifier::new(p.n, p.pk());

        for _ in 0..p.n {
            let ch = v.next_challenge();
            let pwd = p.reply(ch);
            assert_eq!(v.verify(pwd), true);
        }
    }
}
