# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — unreleased

The first public shape of the project. Still unaudited: see
[SECURITY.md](SECURITY.md).

### Added

- `std/recursion`: a generic outer Groth16 verifier circuit. It verifies a
  BN254 or BLS12-381 Groth16 proof inside a BN254 Groth16 circuit, with the
  inner verifying key baked in as a compile-time constant.
- `std/ringpairing`: the curve-agnostic half of the ring pairing — the
  polynomial ring, the Miller loop driver, the deferred product check and the
  `Curve` interface the per-curve packages implement.
- `std/ring_bn254`, `std/ring_bls12381`: the per-curve halves — the twist,
  the G2 ladder, the line shape, the subgroup check and gnark's hints.
- `std/polyring`: the deferred product checker over the polynomial ring,
  following [eprint 2024/640](https://eprint.iacr.org/2024/640).
- `lib/solidity`: a Solidity verifier exporter for proofs carrying more than
  one BSB22 commitment, which gnark's own generator does not support.
- `lib/soltest`: deploys a generated verifier to a simulated EVM so tests can
  check a contract against a real proof.
- `lib/gnarkpairing`: the same outer circuit checked with gnark's in-circuit
  pairing, the baseline polyring is measured against.
- `lib/profile`, `lib/bench`: the Groth16 benchmark over both inner curves
  and both pairings, with a per-phase constraint breakdown and a pprof sweep.
- `examples/mimc`, `examples/recursion`: the inner statement and the
  end-to-end flow, on chain included.

### Known limitations

- Inner circuits that draw their own BSB22 commitments are not supported: the
  outer verifier checks no commitment and no proof of knowledge.
- Nested recursion (an outer proof that is itself recursively verified) is
  not implemented.
- The verifying key is a compile-time constant; there is no variable-key
  verification.
- One proof per outer proof; there is no aggregation of several inner proofs.

[Unreleased]: https://github.com/mistcash/polyring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mistcash/polyring/releases/tag/v0.1.0
