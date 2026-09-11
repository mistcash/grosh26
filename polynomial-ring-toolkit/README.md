# polynomial-ring-toolkit

A deferred product checker for polynomial rings `𝔽p[x]/(mod)` inside
[gnark](https://github.com/Consensys/gnark) circuits, where `𝔽p` is a field
emulated in the circuit's native field.

Emulating a large field inside a smaller one is expensive because every
product has to be reduced against the field modulus as soon as it is
computed. This module takes the other route: the prover *claims* a product
and its quotient through a hint, and every claim a circuit makes is batched
into one polynomial identity, checked at a single random point after
`Define` returns.

Nothing here is specific to a curve, a pairing, or a proof system. The
modulus is whatever polynomial you register, the coefficient field is any
`emulated.FieldParams`, and one checker can hold several rings at once. If
your structure's multiplication is polynomial multiplication modulo a fixed
polynomial, it fits.

**This module is unaudited.** It has not had an external cryptographic
review. See [`docs/review-spec.md`](docs/review-spec.md) for the soundness
arguments and the deliberate deviations, stated explicitly.

## Install

```sh
go get github.com/mistcash/polynomial-ring-toolkit
```

The module pins [tiny-gnark's `pre-merge`
branch](https://github.com/mistcash/tiny-gnark/tree/pre-merge) through a
`replace` directive — a fork that keeps the upstream module path, so every
import still reads `github.com/consensys/gnark`. **A consuming module has to
carry that same `replace` directive**, because Go ignores `replace` in
dependencies. See [Commitments](#commitments) for why it is needed.

## Use

```go
import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/polyring"
)

type Fp = emulated.BN254Fp

// A, B are the two ring elements, four coefficients each, ascending in degree.
type Circuit struct {
	A, B [4]emulated.Element[Fp]
}

func (c *Circuit) Define(api frontend.API) error {
	// Construct the checker before anything else creates an emulated field.
	prc := polyring.NewPolyRingChecker[Fp](api)

	// Register a ring. Here 𝔽p[x]/(x⁴ − 2); coefficients ascend in degree.
	ring := prc.NewPolyRingCheck(prc.MakePoly(-2, 0, 0, 0, 1), nil)

	a := &polyring.Poly[Fp]{Coeffs: []*emulated.Element[Fp]{&c.A[0], &c.A[1], &c.A[2], &c.A[3]}}
	b := &polyring.Poly[Fp]{Coeffs: []*emulated.Element[Fp]{&c.B[0], &c.B[1], &c.B[2], &c.B[3]}}

	// Fix the operands before the challenge is drawn.
	ring.ToCommit(a.Coeffs...)
	ring.ToCommit(b.Coeffs...)

	// The product, claimed now and verified once Define returns.
	ab, err := prc.MulPolyRings(ring, a, b)
	if err != nil {
		return err
	}
	_ = ab // a *polyring.Poly[Fp], usable straight away
	return nil
}
```

Two rules, and both are soundness-critical:

- **Construct the checker first.** `NewPolyRingChecker` registers the
  deferred check with the compiler, and gnark runs deferred callbacks in
  registration order. The range checker is registered when the first
  emulated field is created, and the ring checks emit range checks of their
  own, so the checker has to come first or the range checker will already be
  closed when the ring checks run.

- **Commit every prover-chosen operand** with `ToCommit`, before the
  challenge is drawn. Circuit inputs and hinted values alike. It matters most
  for a hinted value whose correctness is asserted by a ring product itself —
  a hinted inverse checked as `x·x⁻¹ = 1 + q·mod` is an operand of that very
  check.

### API

| | |
| --- | --- |
| `NewPolyRingChecker[T](api)` | one per circuit, registers the deferred check |
| `.NewPolyRingCheck(mod, modEvalFn)` | register a ring; pass `nil` to evaluate the modulus generically, or a closure when it is sparse enough to be cheaper |
| `.MakePoly(coeffs...)` | build a polynomial from constants, ascending in degree |
| `.MulPolyRings(ring, inputs...)` | claim a product, get the remainder back now |
| `.NewPolyRingAccumulator(ring, targetDeg)` | queue factors, collapsing into a claim whenever `targetDeg` would be exceeded |
| `.Field()` | the underlying `emulated.Field[T]`, for the coefficient-wise operations that don't go through the ring |
| `group.ToCommit(elements...)` | fix operands before the challenge is drawn |

`Poly[T].Coeffs` is exported, so a type of your own becomes a ring element by
handing over its coefficients — see `PolyConv[T]`. A `nil` coefficient is
zero, which keeps sparse polynomials cheap.

## The protocol

For a ring `𝔽p[x]/(mod)`, each claimed product is the polynomial identity

```
∏ᵢ inputsᵢ = r + q·mod
```

where `r` is the remainder handed back to the caller and `q` the quotient.
Batching many such claims uses two rounds of Fiat-Shamir over the circuit's
commitment scheme, following the Extension Field Arithmetic IOP of
[On Proving Pairings](https://eprint.iacr.org/2024/640.pdf), Section 5.2:

1. commit to every remainder, giving challenge `z`;
2. fold the quotients off-circuit into `qAcc = Σᵢ zⁱ·qᵢ` — this is the
   saving: without folding, every quotient would need its own in-circuit
   evaluation;
3. commit to `qAcc`, giving challenge `x`;
4. assert `Σᵢ zⁱ·(∏ⱼ inputsᵢⱼ(x) − rᵢ(x)) == qAcc(x)·mod(x)`.

By Schwartz-Zippel this is equivalent to every individual claim holding as a
polynomial identity, except with probability at most
`deg/|challenge space|`. Both challenges are carried into the emulated field
at full native width, not truncated; `docs/review-spec.md` §2 says why that
matters.

## Commitments

The protocol draws two BSB22 commitments, and gnark's range checker draws its
own, so a circuit using this module carries at least three. Two consequences
worth knowing before you build on it:

- A verifier generator that handles only one commitment will not work.
  [grosh26](https://github.com/mistcash/grosh26) ships a Solidity generator
  that handles several.
- Stock gnark v0.16.0 miscompiles circuits with more than one commitment:
  `builder.Commit` in `frontend/cs/r1cs` looks an already-committed wire's
  commitment up in a list it has partly consumed, and picks the wrong one or
  runs off the end. Hence the `replace` directive — on stock gnark these
  circuits do not compile at all.

## Who uses it

[grosh26](https://github.com/mistcash/grosh26) is the reference consumer: it
instantiates the ring once, for `x¹² − 18x⁶ + 82`, to run BN254's `𝔽p¹²`
arithmetic — a Miller loop and pairing check — through claimed products
instead of gnark's product-by-product reduction, and builds Groth16
recursion on top.

## Tests

```sh
go test ./...
```

The suite covers the off-circuit Euclidean division directly, and the
in-circuit protocol through `test.IsSolved` over rings (`x⁴ − 2`, `x³ − 5`)
and coefficient fields (BN254, secp256k1, BLS12-377) chosen to have nothing
to do with any pairing. It includes two negative tests: one where the prover
claims the wrong remainder, and one where the product and remainder are
honest but the deferred identity evaluates the wrong modulus, so nothing but
step 4 of the protocol can catch it.

## License

Apache-2.0, see [LICENSE](LICENSE). See [CHANGELOG](CHANGELOG.md) for release
notes.
