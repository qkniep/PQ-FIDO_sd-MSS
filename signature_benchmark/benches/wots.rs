// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::*;
use rand::{thread_rng, RngCore};

use signature_benchmark::wots;

fn wots_cycles_for_msg(c: &mut Criterion) {
    let mut rng = thread_rng();
    let w = wots::Wots::new();
    c.bench_function("WOTS Convert Msg to Cycles", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| wots::cycles_for_msg(&m, &w.pk_hash),
            BatchSize::SmallInput,
        )
    });
}

fn wots_keygen(c: &mut Criterion) {
    //println!("Public Key Size: {}", wots::Wots::new().pk.len() * wots::N);
    c.bench_function("WOTS (SHA-256) KeyGen", |b| b.iter(|| wots::Wots::new()));
}

fn wots_sign(c: &mut Criterion) {
    let mut rng = thread_rng();
    let w = wots::Wots::new();
    println!(
        "Signature Size: {} Bytes",
        w.sign("test123").signature.len() * wots::N
    );
    c.bench_function("WOTS (SHA-256) Sign", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                format!("msg{}", n)
            },
            |m| w.sign(&m),
            BatchSize::SmallInput,
        )
    });
}

fn wots_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    let w = wots::Wots::new();
    c.bench_function("WOTS (SHA-256) Verify", |b| {
        b.iter_batched(
            || {
                let n = rng.next_u32();
                let m = format!("msg{}", n);
                (m.clone(), w.sign(&m))
            },
            |(msg, sig)| sig.verify(&msg),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    wots_cycles_for_msg,
    wots_keygen,
    wots_sign,
    wots_verify
);
criterion_main!(benches);
