// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use core::hash::Hasher;

use aes::cipher::{
    generic_array::GenericArray, BlockEncrypt, NewBlockCipher, NewCipher, StreamCipher,
};
use aes::{Aes128, Aes128Ctr};
use blake3::hash;
use criterion::*;
use hmac::{Hmac, Mac, NewMac};
use rand::{thread_rng, RngCore};
use sha2::{Sha224, Sha256};
use sha3::{Digest, Sha3_224, Sha3_256};
use siphasher::sip128::{Hasher128, SipHasher};

fn hmac(c: &mut Criterion) {
    let mut rng = thread_rng();
    let n = rng.next_u32();
    let key = format!("key{}", n);
    let mut mac = Hmac::<blake3::Hasher>::new_varkey(key.as_bytes()).unwrap();
    c.bench_function("HMAC (Blake3)", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                let msg = format!("msg{}", n);
                hash(msg.as_bytes())
            },
            |msg| {
                mac.update(msg.as_bytes());
                mac.finalize_reset()
            },
            BatchSize::SmallInput,
        )
    });
}

fn aes_ctr(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut block = [0u8; 16];
    rng.fill_bytes(&mut block);
    let key = GenericArray::clone_from_slice(&block);
    rng.fill_bytes(&mut block);
    let nonce = GenericArray::clone_from_slice(&block);

    let mut cipher = Aes128Ctr::new(&key, &nonce);
    c.bench_function("AES-128-CTR", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let mut block = [0u8; 16];
                rng.fill_bytes(&mut block);
                block
            },
            |mut b| {
                cipher.apply_keystream(&mut b);
            },
            BatchSize::SmallInput,
        )
    });
}

fn aes_mmo(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut block = [0u8; 16];
    rng.fill_bytes(&mut block);
    let iv = GenericArray::clone_from_slice(&block);

    let cipher = Aes128::new(&iv);
    c.bench_function("AES-128-MMO", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let mut block = [0u8; 16];
                rng.fill_bytes(&mut block);
                //block
                (block, GenericArray::from(block))
            },
            |(b, mut ga)| {
                //let mut ga = GenericArray::from(b);
                let i = u128::from_be_bytes(b.clone());
                cipher.encrypt_block(&mut ga);
                let o = u128::from_be_bytes(b.clone());
                let r = i ^ o;
                return GenericArray::from(r.to_be_bytes());
            },
            BatchSize::SmallInput,
        )
    });
}

fn blake3(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("Blake3", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| hash(m.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn sha2_224(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SHA2-224", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| Sha224::digest(m.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn sha2_256(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SHA2-256", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| Sha256::digest(m.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn sha3_224(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SHA3-224", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| Sha3_224::digest(m.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn sha3_256(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SHA3-256", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| Sha3_256::digest(m.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn siphash(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut hasher = SipHasher::new();
    c.bench_function("SipHash", |b| {
        b.iter_batched(
            || {
                // Generate new message to sign
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| {
                hasher.write(m.as_bytes());
                hasher.finish128()
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches, hmac, aes_ctr, aes_mmo, blake3, sha2_224, sha2_256, sha3_224, sha3_256, siphash
);
criterion_main!(benches);
