# How it works

This is the longer version of the readme's [How it works](https://github.com/mistcash/polyring#how-it-works)
section: what the circuit actually does, and why each piece is the shape it
is.

The technique follows [On Proving Pairings](https://eprint.iacr.org/2024/640)
(Novakovic, Eagen), which does three things: it replaces the final
exponentiation with a residue check folded into the Miller loop, it
precomputes the lines of a fixed pairing argument, and it batches the
quotients of the polynomial product checks.

## The Groth16 identity

Verifying a Groth16 proof is checking

```
e(A, B) · e(α, β)⁻¹ · e(L, γ)⁻¹ · e(C, δ)⁻¹ = 1
```

where `A`, `B`, `C` are the proof's points, `α`, `β`, `γ`, `δ` come from the
verifying key, and `L` is the recombination of the key's `K` points with the
public inputs.

gnark's in-circuit pairing runs a full Miller loop over 𝔽p¹² for every pair,
then a final exponentiation. That is the expensive part of the verifier
circuit.

polyring's outer circuit checks the same identity, but:

- only `e(A, B)` runs a full Miller loop — `B` is the one point in the
  witness that is not fixed;
- `e(L, γ)⁻¹` and `e(C, δ)⁻¹` use precomputed lines, so their ladders and
  subgroup checks never enter the circuit at all;
- `e(α, β)⁻¹` has both points fixed, so its Miller loop value is a
  compile-time constant, folded into the check as a single factor.

That leaves one Miller loop instead of four, and the lines it accumulates are
evaluated over a polynomial ring rather than 𝔽p¹².

## The ring

The pairing is evaluated over

```
𝔽p[w] / (w¹² − 2ξ₀w⁶ + ξ₀² + 1)
```

For BN254, ξ₀ = 9, so the modulus is `x¹² − 18x⁶ + 82`. For BLS12-381,
ξ₀ = 1, so it is `x¹² − 2x⁶ + 2`.

A ring element is a degree-11 polynomial over 𝔽p, held as twelve emulated
field elements. The point of the ring is that a Miller loop's line
evaluations are *sparse* polynomials — a line puts three terms on a handful
of powers of `w` — and multiplying sparse polynomials is much cheaper in the
ring than reducing a sparse 𝔽p¹² product.

The shared core (`std/ringpairing`) knows nothing about 𝔽p² or G2. It owns:

- the ring itself, and how 𝔽p² elements embed into it;
- the Miller loop driver, and the schedule it runs;
- the deferred product check, and the residue check.

Each curve package (`std/ring_bn254`, `std/ring_bls12381`) owns its twist:
the G2 ladder, the line shape, the subgroup check, the loop counter and
gnark's hints. The boundary between them is the `ringpairing.Curve`
interface.

## The deferred product check

A Miller loop is a sequence of products, and each product in the ring is
polynomial division: `∏ inputs = r + q · mod`, with `r` the remainder and
`q` the quotient. Evaluating those products in-circuit would mean evaluating
the quotients too, which is where most of the cost lives.

Instead, the products are *deferred*. The prover supplies `r` and `q` through
a hint, and the circuit checks the identity at one random point `x`
(Schwartz–Zippel):

```
∏_i inputs_i(x) = r(x) + q(x) · mod(x)
```

Two things make this cheap:

- **The quotients are batched outside the circuit.** The prover computes a
  random linear combination `∑_i z^i · q_i` in a hint and commits to it, so
  many quotients cost one in-circuit evaluation instead of one each. The
  challenge `z` is the commitment's own randomness, and `x` is drawn after
  `z` is committed, so the prover cannot grind it.
- **The accumulator's degree is bounded.** A Miller iteration squares the
  running value and multiplies in lines of degree 8 or 9, so the degree
  doubles each step. `std/ringpairing` caps the accumulated degree at 69 and
  collapses into a check whenever it would be exceeded, which keeps the
  number of in-circuit products independent of the loop length.

This is where the extra commitments come from. Each deferred check commits to
its remainders and to the batched quotients, and gnark's emulated-field range
checker commits once more: three BSB22 commitments in total, where gnark's
in-circuit pairing needs one.

## The residue check

The final exponentiation is the other half of the cost. eprint 2024/640
replaces it with a *residue check*: the prover supplies a witness `c` such
that the Miller loop's raw value relates to `c^(-λ)`, and the check folds `c`
into the loop as a seed. The tail of the check supplies the Frobenius powers
that complete `c^(-λ)`, and the whole product is asserted to be one.

`std/ringpairing.Pairing.PairingCheck` does this. The `previous` argument
carries the fixed `e(α, β)` term in.

## The fixed pairs

`γ` and `δ` never vary: they are constants of the verifying key. A pairing
whose second argument is fixed can have all its line evaluations computed
off-circuit, and the ladder — and with it the on-twist and subgroup checks —
leaves the circuit entirely. gnark's `sw_bn254.NewG2AffineFixed` and
`sw_bls12381.NewG2AffineFixed` carry those precomputed lines.

`B` is the exception: it comes from the witness, so its ladder runs
in-circuit. That ladder is also what asserts `B` is on the twist and in G2,
which is why there is no separate `AssertIsOnG2` for it — a separate check
would repeat the work at around 100k constraints.

Because `β`, `γ` and `δ` skip the ladder, nothing in the circuit would catch
a malformed key point. `recursion.NewVerifyingKey` checks them up front
instead: they, and `α`, have to be in their subgroups and not the point at
infinity.

## The K-sum

`L` is `k[0] + Σ k[i+1] · public[i]`, with the `k[i]` constants and the
`public[i]` prover-influenced. Two summands landing on equal or negated
points is possible when the public inputs are adversarial, so the sum is
accumulated with complete addition: `MultiScalarMul` for the scalar
multiples, then `AddUnified` for the constant term. gnark's own reference
verifier folds with `Add` in the same place, which is safe there only
because `K[0]` is a fixed constant summed once at the end.
