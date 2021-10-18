// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use blake3::hash;
use criterion::*;
use pqcrypto::sign::dilithium2::*;
use rand::{thread_rng, RngCore};

fn dilithium_keygen(c: &mut Criterion) {
    c.bench_function("Dilithium2 KeyGen", |b| b.iter(|| keypair()));
}

fn dilithium_sign(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (_, sk) = keypair();
    c.bench_function("Dilithium2 Sign", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                let s = format!("msg{}", n);
                let h = hash(s.as_bytes()).to_hex();
                (h, sk)
            },
            |(h, sk)| sign(black_box(h.as_bytes()), &sk),
            BatchSize::SmallInput,
        )
    });
}

fn dilithium_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (pk, sk) = keypair();
    c.bench_function("Dilithium2 Verify", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                let s = format!("msg{}", n);
                let h = hash(s.as_bytes()).to_hex();
                let msg = sign(black_box(h.as_bytes()), &sk);
                (msg, pk)
            },
            |(msg, pk)| open(&msg, &pk),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, dilithium_keygen, dilithium_sign, dilithium_verify);
criterion_main!(benches);
