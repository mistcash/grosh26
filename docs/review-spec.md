# Review specification

Entry point for a cryptographer reviewing this repo's novel surface: the
deferred polynomial ring check, the BN254 ring pairing built on it, the
Groth16-in-Groth16 recursion, and the multi-commitment Solidity verifier.
Everything else — point arithmetic, subgroup checks, the Frobenius maps and
tower conversions, Groth16 setup/prove/verify — is gnark's, used unmodified,
and out of scope here.

This document states the shipped protocol and its soundness arguments as of
v0.1.0, including the deliberate deviations from the constructions it draws
on and the open questions this repo has not yet resolved. Where an argument
depends on a specific line of code, the reference is given so it can be
checked against the current source rather than taken on faith.

## 1. The deferred ring check protocol (`std/polyring/field_polyring.go`)

### 1.1 The idea

Emulating a large field inside a small one is expensive because every
product has to be reduced against the field's modulus polynomial as soon as
it is computed. `PolyRingChecker` takes the other route: a product is
*claimed* — the prover supplies its quotient and remainder through a hint —
and every claim made anywhere in the circuit is verified together, as a
single batched polynomial identity checked at a random point after `Define`
returns (`api.Compiler().Defer`, `performDeferredRingChecks`,
`std/polyring/field_polyring.go:39,447`).

Concretely, for a ring `𝔽p[x]/(mod)`, each claimed product
`∏ᵢ inputsᵢ = r + q·mod` is a polynomial identity. Batching many such claims
(possibly against different input polynomials but the same modulus) uses two
rounds of Fiat-Shamir, mirroring the "Extension Field Arithmetic IOP" of
[On Proving Pairings, eprint 2024/640](https://eprint.iacr.org/2024/640.pdf),
Section 5.2:

1. **Commit the remainders.** The prover has already committed to every
   product's remainder `r` (via gnark's BSB22 `Commit`, which folds all
   committed wires into one Pedersen commitment and derives its opening via
   `gnark-crypto`'s `fr.Hash` — RFC 9380 `hash_to_field` with
   `expand_message_xmd`/SHA-256, domain tag `G16-BSB22`; the commitment
   itself *is* the Fiat-Shamir challenge, so there is no separate in-circuit
   hash). This is challenge `z` (`std/polyring/field_polyring.go:485`).
2. **Fold the quotients.** `qAcc = Σᵢ zⁱ·qᵢ`, computed by a hint outside the
   circuit (`callQuotientsRLCHint`, `std/polyring/field_polyring.go:613`) — this is the
   protocol's saving: without folding, every quotient would need its own
   in-circuit evaluation.
3. **Commit the folded quotient**, giving challenge `x`
   (`std/polyring/field_polyring.go:517`).
4. **Assert the identity at `x`**:
   `Σᵢ zⁱ·(∏ⱼ inputsᵢⱼ(x) − rᵢ(x)) == qAcc(x)·mod(x)`
   (`std/polyring/field_polyring.go:560-598`), by Schwartz-Zippel equivalent to every
   individual claim holding as a polynomial identity, except with
   probability at most `deg/|challenge space|` over the prover's choice of a
   false claim.

`std/ring_bn254` instantiates this once, for `mod = x¹² − 18x⁶ + 82` (BN254's
𝔽p¹² modulus), registering the ring group in `NewExt12`
(`std/ring_bn254/ring.go:48`). Every 𝔽p¹² product in the Miller loop and the
residue-witness tail (`std/ring_bn254/pairing.go`) is queued through this
ring rather than reduced coefficient-wise.

### 1.2 Full-width challenge derivation

Both `z` and `x` are native field elements — outputs of gnark's `Commit`,
already Fiat-Shamir randomness by construction (§1.1). To evaluate the
polynomial identity in step 4, which lives in the emulated field `𝔽p`
(BN254's base field, distinct from the circuit's native scalar field), each
challenge has to be re-expressed as an emulated field element:
`NativeToEmulated` (`std/polyring/field_polyring.go:773`) decomposes the native value into
`nbBits`-wide limbs via a hint, and asserts the decomposition reconstructs
the original native value exactly (`AssertIsEqual(rebuildEl, v[i])`) before
handing back the limbs as an `Element[T]`.

Before this ticket (#5), the function then discarded everything past the
first two limbs (`elements[i].Limbs = elements[i].Limbs[:2]`), so only the
low ~128 bits of an already-verified, fully-reconstructed native value were
used as the emulated challenge. Now (`fullChallengeLimbs`,
`std/polyring/field_polyring.go:773-778`) it keeps every limb the native field needs —
`FieldBitLen()/nbBits + 1` of them — matching the eprint's construction of
using the verifier's (here: the commitment's) randomness directly, in full,
rather than a further-truncated derivative of it. `callQuotientsRLCHint`'s
native-side masking of `z` (`std/polyring/field_polyring.go:667-673`) uses the same width,
so the off-circuit RLC computation and the in-circuit identity check agree
on the same challenge value.

**Soundness note, for context:** even the pre-#5 truncation already gave a
Schwartz-Zippel soundness error of at most `deg/2^128` — negligible for the
degrees here (`accumulatorTargetDegree = 69` bounds every queued product,
`std/ring_bn254/pairing.go:28`). The full-width change is not closing a
practical attack; it is bringing the implementation in line with the letter
of the referenced construction. Measured cost at the time: the two-pair
check grew from 654,095 to 659,592 constraints (+0.84%), recorded on #5.

### 1.3 The quotient coefficients carry no range check — deliberately

`MulPolyRings` builds the returned quotient's limbs with
`prc.f.UnsafeFromLimbs` (`std/polyring/field_polyring.go:227`), which skips the range
check `prc.f.NewElement` would otherwise perform. The remainder `r`, by
contrast, *is* built with `prc.f.NewElement` (`std/polyring/field_polyring.go:236`) and so
is range-checked.

This asymmetry is intentional. The quotient is never used for anything
except the one deferred identity it exists to satisfy
(`qAcc(x)·mod(x)`, §1.1 step 4); nothing else in the circuit reads it. An
out-of-range quotient limb representation can only change whether that one
`AssertIsEqual` — a genuine equality of reduced field elements, since
`Field.AssertIsEqual` reduces both operands — holds; Schwartz-Zippel already
governs exactly that outcome, independent of how the quotient's limbs happen
to be arranged below the modulus. There is no second constraint an
out-of-range quotient could exploit to smuggle in extra freedom. The
remainder, in contrast, is range-checked because it flows onward into
coefficient-wise (non-ring) circuit operations, where an out-of-range
representation would be a genuine soundness gap.

## 2. Recursion composition (`std/recursion`, `examples/poseidon`)

### 2.1 What it demonstrates

A Groth16 verifier, expressed as a circuit, so that one Groth16 proof (the
*outer* proof) attests that another Groth16 proof (the *inner* proof, over
an unrelated statement) verifies. The inner circuit
(`examples/poseidon.Circuit`) is deliberately small — knowledge of a
preimage to a Poseidon2 2-to-1 compression digest — to keep the interesting
cost in the outer circuit alone.

### 2.2 The pairing identity, checked through the ring

Groth16 verification is the pairing identity
`e(A,B)·e(α,β)⁻¹·e(L,γ)⁻¹·e(C,δ)⁻¹ = 1`, where `L` is the public-input linear
combination `Σᵢ wᵢ·Kᵢ + K₀`. `Verifier.AssertProof`
(`std/recursion/verifier.go`) negates `α` (G1) and `γ`, `δ` (G2) once at
verifying-key-construction time (`NewVerifyingKey`), so the whole thing
becomes one four-term `PairingCheck` through the ring pairing of §1.

Only one of the four terms is a full pairing. `β`, `γ` and `δ` come from the
verifying key and never vary, so three of the four in-circuit `[6x₀+2]Q`
ladders are avoidable, and the check is assembled from one full pair plus
three fixed-Q pairs:

| term | shape | what the circuit does |
| --- | --- | --- |
| `e(A,B)` | witness `Q` | full pairing: `B`'s ladder and G2 subgroup check run in-circuit |
| `e(α,β)⁻¹`, `e(L,γ)⁻¹`, `e(C,δ)⁻¹` | `sw_bn254.NewG2AffineFixed` | fixed Q: the lines are precomputed off-circuit, only the G1 side varies |

That is one Miller loop over four G1 points with a single in-circuit
ladder, and it is what takes the outer circuit from 1,269,953 constraints
to 660,886 (−48.0%).

The soundness cost of skipping a ladder is that the G2 subgroup check goes
with it, so it has to happen somewhere else. `sw_bn254.NewG2AffineFixed`
runs it off-circuit, on the native point, and panics on a point outside the
subgroup. Since the point is a
compile-time constant, an off-circuit check is a check on exactly the value
the circuit will use — there is no witness for a prover to vary. It is,
however, the only check: nothing downstream would catch a malformed `β`, `γ`
or `δ`, which is what `TestOuterCircuitRejectsMalformedKey` pins.

Which of gnark-crypto's two Miller loops the raw value matches matters here
and is easy to get wrong: it has to use the same line normalisation the
in-circuit loop does, i.e. gnark-crypto's `MillerLoopFixedQ` (affine lines),
not `MillerLoop` (projective, whose raw value carries the lines' `Z`
factors). They differ by a factor the final exponentiation would kill and
this check does not. `TestMillerLoopMatchesFixedQ` pins the in-circuit raw
Miller loop against the former.

### 2.3 The verifying key is baked in as a compile-time constant

The inner circuit's verifying key is not a witness: `NewVerifyingKey`
converts gnark's native `bn254.G1Affine`/`G2Affine` points, and
`NewVerifier` turns each into an in-circuit constant the same way gnark
does -- `sw_bn254.NewG1Affine` for G1 and `sw_bn254.NewG2AffineFixed` for G2,
both built on `emulated.ValueOf`.
That is sound here: gnark's `enforceWidthConditional`
(`std/math/emulated/field.go`) calls `Initialize()` on a `ValueOf`-built
constant the first time any arithmetic op touches it, which the pairing
check always does.

### 2.4 Field-registration ordering

`ring_bn254.NewPairing` (and so the `PolyRingChecker` it wraps) must be
constructed before anything else in the circuit creates an emulated field or
range checker. gnark runs deferred callbacks in registration order; the
range checker (created by the first emulated field, whoever creates it) has
to be registered *after* the ring's deferred check or it will already be
closed by the time the ring check tries to emit its own range checks. This
is documented on `NewExt12` (`std/ring_bn254/ring.go:40-47`) and was
re-discovered empirically while building `std/recursion.NewVerifier`, which
now calls `ring_bn254.NewPairing` first for exactly this reason.

### 2.5 The public-input sum uses complete addition

`AssertProof` accumulates the public-input terms of `L` (`Σᵢ wᵢ·Kᵢ`) with
`curve.MultiScalarMul` (`std/recursion/verifier.go`), then folds in the
constant term `K₀` with `curve.AddUnified`. This matches gnark's own
reference Groth16-in-circuit verifier
(`std/recursion/groth16/verifier.go:595-599` in the vendored fork), which
routes the same sum through `MultiScalarMul` and then a single `Add` for
`K₀`; this repo uses `AddUnified` rather than plain `Add` for that last fold,
which costs the same for a single addition and removes even that residual
incomplete-addition edge.

Previously this accumulated the terms one at a time with `curve.Add`
(gnark's *incomplete* addition formula: `sw_emulated.Curve.add` computes
`λ = (q.y−p.y)/(q.x−p.x)` with no handling for `p == q` or `p == −q`), with
no argument for why the `k[i]` constants and the prover-influenced
public-input scalar multiples could never collide in x-coordinate. Fixed in
#14 by switching to complete addition throughout, rather than attempting
that argument.

### 2.6 Open item: the BSB22-commitment restriction is not structural

v0.1 does not support an inner circuit whose proof carries BSB22 commitments
(`NewVerifyingKey` rejects `len(vk.CommitmentKeys) > 0`, `ValueOfProof`
rejects a non-empty `proof.Commitments`). `AssertProof` itself has no
`Commitments` field and performs no proof-of-knowledge check — the
restriction lives only in the two constructors. Currently a mismatched
proof/VK is caught as a byproduct of `AssertProof`'s public-input length
check, not by a purpose-built guard. Tracked in #17.

## 3. The multi-commitment Solidity verifier (`solidity/`)

### 3.1 Why it exists

gnark's own Solidity generator supports at most one BSB22 commitment
correctly. Every circuit in this repo draws three: two from the ring's
deferred checks (the remainder commitment and the folded-quotient
commitment, §1.1) plus the range checker's own. gnark's template neither
sums more than two commitment points correctly in its public-input MSM nor
derives the challenge that folds more than one commitment's proof of
knowledge. The prover, setup and off-chain verifier are gnark's, unmodified
— they handle multiple commitments fine; only the *generator* is new here.

### 3.2 The folding challenge, reproduced exactly

gnark-crypto's prover derives the challenge that folds multiple commitments'
proofs of knowledge with `fr.Hash` — RFC 9380 `hash_to_field`,
`expand_message_xmd` over SHA-256, domain separation tag `"G16-BSB22"`. The
generated contract's `foldingChallenge` (`solidity/solidity.go:503-512`)
reproduces this construction exactly, in three `sha256` precompile calls,
from the same public commitment hashes the prover folds. This is what lets
the stock gnark prover and this repository's generated verifier agree on the
same challenge without any change to the prover.

### 3.3 Folding the commitments

Mirroring `gnark-crypto`'s `pedersen.BatchVerifyMultiVk`: each commitment
carries its own `GSigmaNeg` (the sigma trapdoor is sampled independently per
commitment key), scaled by successive powers of the folding challenge; the
shared Pedersen `G` (sampled once for the whole circuit — Groth16 setup's
`WithG2Point` invariant, `solidity/solidity.go:100-102`) is checked once
against the already-folded proof of knowledge. The whole fold is verified as
a single `(numCommitments+1)`-pairing check via the `PRECOMPILE_VERIFY`
(BN254 pairing) precompile.

## Summary: deliberate deviations and open items

| # | Item | Status |
| --- | --- | --- |
| 1 | Schwartz-Zippel challenge, full native width vs. 2-limb truncation | Fixed, #5 |
| 2 | Quotient coefficients carry no range check | Deliberate, argued safe in §1.3 |
| 3 | Verifying-key constants built via `Field.NewElement` rather than `emulated.ValueOf` | Deliberate (belt-and-suspenders); both are sound, §2.3 |
| 4 | Public-input sum via incomplete `curve.Add` instead of `MultiScalarMul` | Fixed, #14 |
| 5 | `AssertProof` has no structural BSB22-commitment guard | Open, #17 |
| 6 | `β`, `γ`, `δ` subgroup-checked off-circuit rather than by an in-circuit ladder | Deliberate, argued safe in §2.2 |

## Matches shipped code

This document describes v0.1.0 as shipped, plus the fixed-argument pairing
terms added since (§2.2). If it and the source disagree, the source is
authoritative and this document is stale — flag it.
