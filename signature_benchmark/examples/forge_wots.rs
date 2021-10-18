// Copyright (C) 2021 Quentin Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

/*use blake3::*;
use rayon::prelude::*;

use signature_benchmark::wots::*;

// TODO allow instantiating with different hash functions

fn main() {
    let msg1 = find_good_first_msg();

    // Calculate a signature for msg1 using the secret key.
    let wots = Wots::new();
    let sig1 = wots.sign(&msg1);

    // Find a message which is forgable given msg1 and its signature.
    let msg2 = find_matching_second_msg(&msg1);

    // Forge a signature for msg2 using only public key, msg1 (+ its signature), and msg2.
    let forged_sig = forge_signature(&msg1, sig1, &msg2);

    if forged_sig.verify() {
        println!("Signature verification successful!");
    } else {
        println!("Signature verification failed!");
    }
}

fn find_good_first_msg() -> String {
    let (min_tries, s) = (0..u64::MAX)
        .into_par_iter()
        .map(|i| {
            let msg = format!("original-{}", i);
            (tries_needed(&msg), msg)
        })
        .find_any(|(t, _)| *t < 1u64 << 16 * X)
        .unwrap();

    println!("the best message ({}) needs only {} tries", s, min_tries);

    return s;
}

fn find_matching_second_msg(msg1: &str) -> String {
    let msg1_hash = hash(msg1.as_bytes());

    let pos = (0..usize::MAX)
        .into_par_iter()
        .map(|i| format!("forged-{}", i))
        .position_any(|m| can_forge(&msg1_hash, &m))
        .unwrap();

    let msg2 = format!("forged-{}", pos);
    println!("found forgable message ({}) for {}", msg2, msg1);

    return msg2;
}

/// Generate a forged signature for message msg2.
fn forge_signature(msg1: &str, sig1: WotsSignature, msg2: &str) -> WotsSignature {
    let h1 = hash(msg1.as_bytes());
    let h2 = hash(msg2.as_bytes());
    let h1b = h1.as_bytes();
    let h2b = h2.as_bytes();

    let mut sig2 = WotsSignature {
        w: sig1.w,
        pk: sig1.pk,
        input: h2b.clone(),
        signature: sig1.signature,
    };

    for i in 0..N {
        let s1 = base_w(h1b[i]);
        let s2 = base_w(h2b[i]);

        for s in 0..X {
            let index = X * i + s;
            sig2.signature[index] = blake_hash(&sig2.signature[index], (s2[s] - s1[s]) as usize);
        }
    }

    return sig2;
}

fn tries_needed(msg: &str) -> u64 {
    let h = hash(msg.as_bytes());

    let mut tries = 1.0;
    for b in h.as_bytes() {
        let symbols = base_w(*b);

        for s in 0..X {
            tries *= W as f64 / (W as f64 - symbols[s] as f64);
        }
    }

    return tries.round() as u64;
}

fn can_forge(msg1_hash: &Hash, msg2: &str) -> bool {
    let h2 = hash(msg2.as_bytes());
    let h1b = msg1_hash.as_bytes();
    let h2b = h2.as_bytes();

    for i in 0..N {
        let s1 = base_w(h1b[i]);
        let s2 = base_w(h2b[i]);

        for s in 0..X {
            if s2[s] < s1[s] || s2[s] < s1[s] {
                return false;
            }
        }
    }

    return true;
}*/

fn main() {}
