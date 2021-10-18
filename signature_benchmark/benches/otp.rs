// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::*;
use rand::{thread_rng, RngCore};

use signature_benchmark::lamport_otp;
use signature_benchmark::park_otp;

fn lamport_init(c: &mut Criterion) {
    c.bench_function("Lamport OTP Init (n=128)", |b| {
        b.iter(|| lamport_otp::Proofer::new(128).pk())
    });
}

fn lamport_gen(c: &mut Criterion) {
    let mut p = lamport_otp::Proofer::new(128);
    let mut v = lamport_otp::Verifier::new(128, p.pk());
    let ch = v.next_challenge();
    c.bench_function("Lamport OTP GenPwd (n=128, WC)", |b| b.iter(|| p.reply(ch)));
}

fn lamport_verify(c: &mut Criterion) {
    let mut p = lamport_otp::Proofer::new(128);
    let mut v = lamport_otp::Verifier::new(128, p.pk());
    let ch = v.next_challenge();
    let pwd = p.reply(ch);
    c.bench_function("Lamport OTP VerifyPwd (n=128, WC)", |b| {
        b.iter(|| v.verify(pwd))
    });
}

fn park_init(c: &mut Criterion) {
    c.bench_function("Park OTP Init", |b| {
        b.iter(|| park_otp::Proofer::new().pk())
    });
}

fn park_gen(c: &mut Criterion) {
    let mut p = park_otp::Proofer::new();
    let mut v = park_otp::Verifier::new(p.pk());
    c.bench_function("Park OTP GenPwd", |b| {
        b.iter_batched(
            || v.next_challenge(),
            |ch| p.reply(ch),
            BatchSize::SmallInput,
        )
    });
}

fn park_verify(c: &mut Criterion) {
    let mut p = park_otp::Proofer::new();
    let mut v = park_otp::Verifier::new(p.pk());

    // start at random point in chain
    let mut rng = thread_rng();
    let n = rng.next_u32() % 1000;

    let mut ch = v.next_challenge();
    let mut pwd = p.reply(ch);
    for _ in 0..n {
        ch = v.next_challenge();
        pwd = p.reply(ch);
    }

    c.bench_function("Park OTP VerifyPwd", |b| b.iter(|| v.verify(pwd)));
}

criterion_group!(lamport, lamport_init, lamport_gen, lamport_verify);
criterion_group!(park, park_init, park_gen, park_verify);
criterion_main!(lamport, park);
