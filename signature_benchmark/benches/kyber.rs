// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::*;
use pqcrypto::kem::kyber512::*;

fn kyber512_keygen(c: &mut Criterion) {
    c.bench_function("Kyber512 KeyGen", |b| b.iter(|| keypair()));
}

fn kyber512_enc(c: &mut Criterion) {
    let (pk, _) = keypair();
    c.bench_function("Kyber512 Enc", |b| b.iter(|| encapsulate(&pk)));
}

fn kyber512_dec(c: &mut Criterion) {
    let (pk, sk) = keypair();
    c.bench_function("Kyber512 Dec", |b| {
        b.iter_batched(
            || encapsulate(&pk),
            |(_, ct)| decapsulate(&ct, &sk),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, kyber512_keygen, kyber512_enc, kyber512_dec);
criterion_main!(benches);
