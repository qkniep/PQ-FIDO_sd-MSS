// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::*;
use rand::{thread_rng, RngCore};

use signature_benchmark::merkle::UpdatableMerkleKeypair;

fn merkle_keygen(c: &mut Criterion) {
    c.bench_function("MSS-WOTS (7, 7, false) - KeyGen", |b| {
        b.iter(|| UpdatableMerkleKeypair::new(7, 7, false))
    });
}

fn merkle_sign(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("MSS-WOTS (7, 7, false) - Sign", |b| {
        b.iter_with_setup(
            || {
                let mss = UpdatableMerkleKeypair::new(7, 7, false);
                let n = rng.next_u32();
                (mss, format!("msg{}", n))
            },
            |(mut mss, msg)| mss.sign(&msg),
        );
    });
}

fn merkle_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("MSS-WOTS (7, 7, false) - Verify", |b| {
        b.iter_with_setup(
            || {
                let mut mss = UpdatableMerkleKeypair::new(7, 7, false);
                let n = rng.next_u32();
                let msg = format!("msg{}", n);
                let sig = mss.sign(&msg);
                (mss, msg, sig)
            },
            |(mss, msg, sig)| sig.verify(&msg, mss.pk),
        )
    });
}

fn merkle_keygen_small_ssc(c: &mut Criterion) {
    c.bench_function("MSS-WOTS (3, 3, true) - KeyGen", |b| {
        b.iter(|| UpdatableMerkleKeypair::new(3, 3, true))
    });
}

fn merkle_sign_small_ssc(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("MSS-WOTS (3, 3, true) - Sign", |b| {
        b.iter_with_setup(
            || {
                let mss = UpdatableMerkleKeypair::new(3, 3, true);
                let n = rng.next_u32();
                (mss, format!("msg{}", n))
            },
            |(mut mss, msg)| mss.sign(&msg),
        );
    });
}

fn merkle_verify_small_ssc(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("MSS-WOTS (3, 3, true) - Verify", |b| {
        b.iter_with_setup(
            || {
                let mut mss = UpdatableMerkleKeypair::new(3, 3, true);
                let n = rng.next_u32();
                let msg = format!("msg{}", n);
                let sig = mss.sign(&msg);
                (mss, msg, sig)
            },
            |(mss, msg, sig)| sig.verify(&msg, mss.pk),
        )
    });
}

criterion_group!(normal, merkle_keygen, merkle_sign, merkle_verify);
criterion_group!(
    small_ssc,
    merkle_keygen_small_ssc,
    merkle_sign_small_ssc,
    merkle_verify_small_ssc
);
criterion_main!(normal, small_ssc);
