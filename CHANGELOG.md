# Changelog

## Unreleased

- Restructure: the polynomial ring checker moved from the repository root to
  `std/polyring`; `circuits/` is replaced by `examples/` (`examples/poseidon`
  for the inner preimage circuit, `examples/recursion` for the end-to-end
  Groth16-in-Groth16 flow). The standalone pairing demo (`circuits/pairing`)
  and the `cmd/grosh26` CLI are removed; testing is basic `test.IsSolved`
  coverage in the style of gnark's `std/algebra/emulated/sw_bn254`.

- `std/ring_bn254`: pairing arguments that are fixed when the circuit is
  built no longer pay for an in-circuit `[6x₀+2]Q` ladder. A pairing check
  is now assembled from `Pair` values — `NewPair` (both points from the
  witness), `NewFixedQPair` (G2 fixed, its line evaluations precomputed
  off-circuit) and `NewFixedPair` (both fixed, so the pair's Miller loop
  value is one constant factor) — passed to `PairingCheckPairs`.
  `PairingCheck` is unchanged and now delegates to it. The G2 subgroup check
  a skipped ladder would have run happens off-circuit instead, when the pair
  is built.
- `std/recursion`: the outer Groth16 verifier uses that shape — two fixed-Q
  pairs (`e(L,γ)⁻¹`, `e(C,δ)⁻¹`), one full pairing (`e(A,B)`) and `e(α,β)⁻¹`
  as a constant — taking the outer circuit from 1,269,953 constraints to
  640,138, a 49.6% cut for the same statement. `NewVerifier` now rejects a
  verifying key whose β, γ or δ is not a well-formed G2 element.

## v0.1.0

First public release. **Unaudited** — see `docs/review-spec.md` for the
soundness arguments and the one open question
([#17](https://github.com/mistcash/grosh26/issues/17)) an external review
has not yet resolved.

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
