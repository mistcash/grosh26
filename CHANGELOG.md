# Changelog

## Unreleased

- Restructure: the polynomial ring checker moved from the repository root to
  `std/polyring`; `circuits/` is replaced by `examples/` (`examples/poseidon`
  for the inner preimage circuit, `examples/recursion` for the end-to-end
  Groth16-in-Groth16 flow). The standalone pairing demo (`circuits/pairing`)
  and the `cmd/grosh26` CLI are removed; testing is basic `test.IsSolved`
  coverage in the style of gnark's `std/algebra/emulated/sw_bn254`.

- `std/ring_bn254`: pairing arguments that are fixed when the circuit is
  built no longer pay for an in-circuit `[6x₀+2]Q` ladder. `PairingCheck`,
  `MillerLoop` and `Pair` take the points directly: a `Q` with precomputed
  lines (built with `sw_bn254.NewG2AffineFixed`) skips the ladder and the
  subgroup check, the rest run them in-circuit and cache the lines in
  `Q.Lines`. `PairingCheck` also takes an optional previous Miller loop
  value, folded into the product as one factor for fully-fixed pairs. The
  G2 subgroup check a skipped ladder would have run happens off-circuit
  instead, when the fixed point is built.
- `std/recursion`: the outer Groth16 verifier uses that shape — one full
  pairing (`e(A,B)`), two fixed-Q pairs (`e(L,γ)⁻¹`, `e(C,δ)⁻¹`) and
  `e(α,β)⁻¹` as a previous value — taking the outer circuit from 1,269,953
  constraints to 641,744, a 49.5% cut for the same statement.

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
