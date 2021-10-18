// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::*;
use rand::{thread_rng, RngCore};

use signature_benchmark::sdmss::{self, Keypair};

fn sd_merkle_keygen(c: &mut Criterion) {
    c.bench_function("SD-MSS-WOTS KeyGen", |b| b.iter(|| Keypair::new()));
}

fn sd_merkle_sign_min(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SD-MSS-WOTS Sign (min)", |b| {
        b.iter_with_setup(
            || {
                let mss = Keypair::new();
                let n = rng.next_u32();
                (mss, format!("msg{}", n))
            },
            |(mut mss, msg)| mss.sign(&msg, 0, 0),
        );
    });
}

fn sd_merkle_sign_avg(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SD-MSS-WOTS Sign (avg)", |b| {
        b.iter_with_setup(
            || {
                let mut mss = Keypair::new();
                while rng.next_u32() % 2 == 1 {
                    mss.sign("hello", 0, 0);
                }
                let n = rng.next_u32();
                (mss, format!("msg{}", n))
            },
            |(mut mss, msg)| mss.sign(&msg, 0, 0),
        );
    });
}

fn sd_merkle_sign_max(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SD-MSS-WOTS Sign (max)", |b| {
        b.iter_with_setup(
            || {
                let mut mss = Keypair::new();
                for _ in 0..(1 << sdmss::S) {
                    mss.sign("hello", 0, 0);
                }
                let n = rng.next_u32();
                (mss, format!("msg{}", n))
            },
            |(mut mss, msg)| mss.sign(&msg, 0, 0),
        );
    });
}

fn sd_merkle_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("SD-MSS-WOTS Verify", |b| {
        b.iter_with_setup(
            || {
                let mut mss = Keypair::new();
                let n = rng.next_u32();
                let msg = format!("msg{}", n);
                let sig = mss.sign(&msg, 0, 0);
                (mss, msg, sig)
            },
            |(mss, msg, sig)| sig.verify(&msg, mss.shallow.pk, mss.deep.pk),
        )
    });
}

criterion_group!(
    benches,
    sd_merkle_keygen,
    sd_merkle_sign_min,
    sd_merkle_sign_avg,
    sd_merkle_sign_max,
    sd_merkle_verify
);
criterion_main!(benches);
