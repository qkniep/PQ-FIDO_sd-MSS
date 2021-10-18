// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use blake3::*;
use criterion::*;
use ed25519_dalek::{Keypair, Signer, Verifier};
use rand::{rngs::OsRng, thread_rng, RngCore};

fn ecdsa_keygen(c: &mut Criterion) {
    let mut csprng = OsRng {};
    c.bench_function("ECDSA (Ed25519) KeyGen", |b| {
        b.iter(|| Keypair::generate(&mut csprng))
    });
}

fn ecdsa_sign(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut csprng = OsRng {};
    let keys = Keypair::generate(&mut csprng);
    c.bench_function("ECDSA (Ed25519) Sign", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                let s = format!("msg{}", n);
                let h = hash(s.as_bytes()).to_hex();
                h
            },
            |h| keys.sign(h.as_bytes()),
            BatchSize::SmallInput,
        )
    });
}

fn ecdsa_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut csprng = OsRng {};
    let keys = Keypair::generate(&mut csprng);
    let pk = keys.public;
    c.bench_function("ECDSA (Ed25519) Verify", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                let s = format!("msg{}", n);
                let h = hash(s.as_bytes()).to_hex();
                let sig = keys.sign(h.as_bytes());
                (h, sig)
            },
            |(h, sig)| pk.verify(h.as_bytes(), &sig),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, ecdsa_keygen, ecdsa_sign, ecdsa_verify);
criterion_main!(benches);
