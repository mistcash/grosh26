# Changelog

## v0.1.0

First public release.

- Polynomial ring checker (`field_polyring.go`): deferred `𝔽p[x]/(mod)`
  product checks, batched behind a single Schwartz-Zippel identity per
  modulus, with challenges derived at full native field width from
  Fiat-Shamir commitments (following eprint 2024/640).
- `std/ring_bn254`: a BN254 pairing check whose 𝔽p¹² arithmetic runs through
  the ring instead of gnark's product-by-product reduction — 659,592
  constraints against gnark's own `PairingCheck` at 736,686 for the same
  statement, about 10% fewer.
- `circuits/pairing`: the standalone demonstration circuit for the ring
  pairing.
- `circuits/poseidon` and `std/recursion`: a Groth16-in-Groth16 recursion
  demo — an outer `Verifier` circuit that checks a Groth16 proof of a small
  Poseidon2 preimage circuit, itself proved and verified through the ring
  pairing.
- `solidity`: a Solidity verifier generator supporting circuits with more
  than one BSB22 commitment, which gnark's own generator does not — used by
  both demo circuits above, each of which draws three commitments.
- `cmd/grosh26`: a CLI driving the full recursive flow — set up both
  circuits, prove the inner circuit then the outer one, verify, and export
  the Solidity verifier.
