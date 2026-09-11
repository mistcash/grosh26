# Review specification

Entry point for a cryptographer reviewing this module: the deferred
polynomial ring check, its two-round Fiat-Shamir batching, and the way the
challenges cross from the native field into the emulated one.

Everything else the module touches — emulated field arithmetic, range
checks, the commitment scheme — is [gnark]'s, used unmodified, and out of
scope here.

Where an argument depends on a specific line of code, the reference is given
so it can be checked against the current source rather than taken on faith.

## 1. The idea

Emulating a large field inside a smaller one is expensive because every
product has to be reduced against the field's modulus as soon as it is
computed. `PolyRingChecker` takes the other route: a product is *claimed* —
the prover supplies its quotient and remainder through a hint — and every
claim made anywhere in the circuit is verified together, as a single batched
polynomial identity checked at a random point after `Define` returns
(`api.Compiler().Defer`, `performDeferredRingChecks`, `polyring/checker.go`,
`polyring/deferred.go:23`).

Concretely, for a ring `𝔽p[x]/(mod)`, each claimed product
`∏ᵢ inputsᵢ = r + q·mod` is a polynomial identity. Batching many such claims
(possibly against different input polynomials, but sharing a modulus) uses
two rounds of Fiat-Shamir, mirroring the "Extension Field Arithmetic IOP" of
[On Proving Pairings, eprint 2024/640], Section 5.2:

1. **Commit the remainders.** The prover has already committed to every
   product's remainder `r` (via gnark's BSB22 `Commit`, which folds all
   committed wires into one Pedersen commitment and derives its opening via
   `gnark-crypto`'s `fr.Hash` — RFC 9380 `hash_to_field` with
   `expand_message_xmd`/SHA-256, domain tag `G16-BSB22`; the commitment
   itself *is* the Fiat-Shamir challenge, so there is no separate in-circuit
   hash). This is challenge `z` (`polyring/deferred.go:59`).
2. **Fold the quotients.** `qAcc = Σᵢ zⁱ·qᵢ`, computed by a hint outside the
   circuit (`callQuotientsRLCHint`, `polyring/deferred.go:190`) — this is the
   protocol's saving: without folding, every quotient would need its own
   in-circuit evaluation.
3. **Commit the folded quotient**, giving challenge `x`
   (`polyring/deferred.go:91`).
4. **Assert the identity at `x`**:
   `Σᵢ zⁱ·(∏ⱼ inputsᵢⱼ(x) − rᵢ(x)) == qAcc(x)·mod(x)`
   (`polyring/deferred.go:137-175`), by Schwartz-Zippel equivalent to every
   individual claim holding as a polynomial identity, except with
   probability at most `deg/|challenge space|` over the prover's choice of a
   false claim.

A checker may hold several rings at once, each registered with its own
modulus via `NewPolyRingCheck`. They are batched independently — the
identity in step 4 is asserted once per ring — but share the two challenges,
and so cost one pair of commitments between them.

## 2. Full-width challenge derivation

Both `z` and `x` are native field elements — outputs of gnark's `Commit`,
already Fiat-Shamir randomness by construction (§1). To evaluate the
polynomial identity in step 4, which lives in the emulated field `𝔽p`
(distinct from the circuit's native field), each challenge has to be
re-expressed as an emulated field element: `NativeToEmulated`
(`polyring/challenge.go:25`) decomposes the native value into `nbBits`-wide
limbs via a hint, and asserts the decomposition reconstructs the original
native value exactly (`AssertIsEqual(rebuildEl, v[i])`) before handing back
the limbs as an `emulated.Element[T]`.

It keeps every limb the native field needs — `FieldBitLen()/nbBits + 1` of
them (`fullChallengeLimbs`, `polyring/challenge.go:16`) — matching the
eprint's construction of using the verifier's (here: the commitment's)
randomness directly, in full, rather than a truncated derivative of it.
`callQuotientsRLCHint`'s native-side masking of `z`
(`polyring/deferred.go:245-250`) uses the same width, so the off-circuit RLC
computation and the in-circuit identity check agree on the same challenge
value.

If the emulated field is too narrow to hold a native element at that width,
`NativeToEmulated` returns an error rather than truncating. Where it is
*wider* — more limbs than the native field decomposes into — the surplus
high limbs are set to constant zero, which is both free and binding.

**Soundness note, for context:** an earlier version of this code (before
`mistcash/grosh26` #5) truncated the challenge to its low two limbs, i.e.
~128 bits. That already gave a Schwartz-Zippel soundness error of at most
`deg/2^128`, negligible for the degrees involved. The full-width change is
not closing a practical attack; it is bringing the implementation in line
with the letter of the referenced construction.

## 3. The quotient coefficients carry no range check — deliberately

`MulPolyRings` builds the returned quotient's limbs with
`prc.f.UnsafeFromLimbs` (`polyring/mul.go:73-80`), which skips the range check
`prc.f.NewElement` would otherwise perform. The remainder `r`, by contrast,
*is* built with `prc.f.NewElement` (`polyring/mul.go:85-89`) and so is
range-checked.

This asymmetry is intentional. The quotient is never used for anything
except the one deferred identity it exists to satisfy (`qAcc(x)·mod(x)`, §1
step 4); nothing else in the circuit reads it. An out-of-range quotient limb
representation can only change whether that one `AssertIsEqual` — a genuine
equality of reduced field elements, since `Field.AssertIsEqual` reduces both
operands — holds; Schwartz-Zippel already governs exactly that outcome,
independent of how the quotient's limbs happen to be arranged below the
modulus. There is no second constraint an out-of-range quotient could
exploit to smuggle in extra freedom.

The remainder is range-checked because it flows onward into coefficient-wise
(non-ring) circuit operations, where an out-of-range representation would be
a genuine soundness gap.

## 4. What the caller is responsible for

Two obligations sit with the caller, and both are soundness-critical.

**Commit every prover-chosen operand.** The Schwartz-Zippel argument in §1
holds only if the prover fixes the claimed product's operands *before* the
challenge is drawn. `PolyRingChecker` commits the remainders itself, and the
inputs of a claim reach the commitment only through
`PolyRingGroupChecks.ToCommit`. An operand the prover chooses — a circuit
input, and in particular a hinted value whose own correctness is asserted by
a ring product, such as a hinted inverse checked as `x·x⁻¹ = 1 + q·mod` —
must be passed to `ToCommit` or the prover can pick it after seeing the
challenge.

**Register the checker first.** `NewPolyRingChecker` registers the deferred
check with the compiler, and gnark runs deferred callbacks in registration
order. The range checker is registered when the first emulated field is
created, and the ring checks emit range checks of their own, so the checker
has to be constructed before anything else in the circuit creates an
emulated field, or the range checker will already be closed when the ring
checks run.

## 5. Commitment count

The protocol draws two BSB22 commitments (`z` and `x`), and the range
checker draws its own, so a circuit using this module carries at least three.
Two consequences:

- A verifier generator that only handles one commitment will not work. The
  reference consumer, [grosh26], ships a Solidity generator that handles
  several.
- Stock gnark v0.16.0 miscompiles circuits with more than one commitment:
  `builder.Commit` in `frontend/cs/r1cs` looks an already-committed wire's
  commitment up in a list it has partly consumed, and picks the wrong one or
  runs off the end. This module therefore pins [tiny-gnark]'s `pre-merge`
  branch, which carries the fix and keeps the upstream module path.

## Summary: deliberate deviations and open items

| # | Item | Status |
| --- | --- | --- |
| 1 | Schwartz-Zippel challenge, full native width vs. 2-limb truncation | Fixed, `mistcash/grosh26` #5 |
| 2 | Quotient coefficients carry no range check | Deliberate, argued safe in §3 |
| 3 | Operand commitment is the caller's obligation, not enforced structurally | Deliberate, stated in §4 |

## Matches shipped code

This document describes the module as shipped. If it and the source
disagree, the source is authoritative and this document is stale — flag it.

[gnark]: https://github.com/Consensys/gnark
[On Proving Pairings, eprint 2024/640]: https://eprint.iacr.org/2024/640.pdf
[grosh26]: https://github.com/mistcash/grosh26
[tiny-gnark]: https://github.com/mistcash/tiny-gnark/tree/pre-merge
