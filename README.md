# PQ FIDO & sd-MSS
Exploring possibility of PQ FIDO Security Keys based on sd-MSS, a novel few-time signature scheme.
This was created as part of my Master's thesis. The thesis can be found on the [university website](https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2021-05/SAR-PR-2021-05_.pdf).

In `scripts` there are Python scripts for calculating various estimates, creating tables and graphs.

Then there is the `signature_benchmark` Cargo project, which implements three hash-based signature schemes.
In the `signature_benchmark` directory you can run `cargo bench` to run all benchmarks,
this includes not just the three hash-based signature schemes but also ECDSA, Falcon, Dilithium2 and some hash functions and AES.

The hash-based schemes implemented are:
* a variant of the one-time signature scheme W-OTS+
* a sequentially-updatable variant Merkle's signature scheme, which allows efficiently updating the public key after only a few signatures have been used
* shallow-deep tree few-time signature scheme (sd-MSS), which uses two such updatable Merkle trees and is parametrized by their respective heights (s and d)

Finally, the `OpenSK` submodule implements the same three schemes for use in OpenSK and on the nRF52840 board.

## License
The git submodule `OpenSK` lists its own licenses.

Everything else is licensed under the [MIT License](LICENSE).
