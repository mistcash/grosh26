package polyring

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// The rings exercised here -- 𝔽p[x]/(x⁴−2), 𝔽p[x]/(x³−5) -- are deliberately
// unrelated to any pairing or proof system. The checker only ever sees a
// modulus and a coefficient field, and these tests keep it that way.

// xnMinusC returns the coefficients of xⁿ − c in the form MakePoly takes.
func xnMinusC(n, c int) []any {
	coeffs := make([]any, n+1)
	for i := range coeffs {
		coeffs[i] = 0
	}
	coeffs[0] = -c
	coeffs[n] = 1
	return coeffs
}

// refMul multiplies polynomials in 𝔽p[x]/(xⁿ − c) by schoolbook multiplication
// followed by repeated substitution of xⁿ ≡ c. It shares no code with
// [polyRingMul], so the circuit is not being checked against itself.
func refMul(p *big.Int, n int, c *big.Int, polys ...[]*big.Int) []*big.Int {
	acc := polys[0]
	for _, poly := range polys[1:] {
		prod := make([]*big.Int, len(acc)+len(poly)-1)
		for i := range prod {
			prod[i] = new(big.Int)
		}
		for i, ai := range acc {
			for j, bj := range poly {
				prod[i+j].Add(prod[i+j], new(big.Int).Mul(ai, bj))
				prod[i+j].Mod(prod[i+j], p)
			}
		}
		for i := len(prod) - 1; i >= n; i-- {
			prod[i-n].Add(prod[i-n], new(big.Int).Mul(prod[i], c))
			prod[i-n].Mod(prod[i-n], p)
			prod[i].SetInt64(0)
		}
		acc = prod[:n]
	}
	// pad to the full n coefficients the checker returns
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = new(big.Int)
		if i < len(acc) {
			out[i].Set(acc[i])
		}
	}
	return out
}

// randPolys returns nb deterministic polynomials of deg coefficients each,
// drawn uniformly below p.
func randPolys(p *big.Int, seed int64, nb, deg int) [][]*big.Int {
	rng := rand.New(rand.NewSource(seed))
	out := make([][]*big.Int, nb)
	for i := range out {
		out[i] = make([]*big.Int, deg)
		for j := range out[i] {
			out[i][j] = new(big.Int).Rand(rng, p)
		}
	}
	return out
}

func elems[T emulated.FieldParams](vs []*big.Int) []emulated.Element[T] {
	out := make([]emulated.Element[T], len(vs))
	for i, v := range vs {
		out[i] = emulated.ValueOf[T](v)
	}
	return out
}

func poly[T emulated.FieldParams](els []emulated.Element[T]) *Poly[T] {
	coeffs := make([]*emulated.Element[T], len(els))
	for i := range els {
		coeffs[i] = &els[i]
	}
	return &Poly[T]{Coeffs: coeffs}
}

func assertCoeffs[T emulated.FieldParams](f *emulated.Field[T], got *Poly[T], want []emulated.Element[T]) error {
	if len(got.Coeffs) != len(want) {
		return fmt.Errorf("remainder has %d coefficients, want %d", len(got.Coeffs), len(want))
	}
	for i := range want {
		f.AssertIsEqual(got.Coeffs[i], &want[i])
	}
	return nil
}

// mulCircuit claims a single product in 𝔽p[x]/(xⁿ − c) and checks the
// remainder the checker hands back.
type mulCircuit[T emulated.FieldParams] struct {
	A, B, Want []emulated.Element[T]

	// set on the circuit value, not carried in the witness
	n, c int
	// when set, the deferred identity evaluates xⁿ − (c+1) instead of the
	// registered modulus. A func field would do this more directly, but gnark's
	// shallowClone compares the clone with reflect.DeepEqual, which is false for
	// any non-nil func.
	wrongModEval bool
}

func (c *mulCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)

	var modEval EvalFnType[T]
	if c.wrongModEval {
		f, n, off := prc.Field(), c.n, c.c+1
		modEval = func(xPowers []*emulated.Element[T]) *emulated.Element[T] {
			return f.Sub(xPowers[n], f.NewElement(off))
		}
	}
	ring := prc.NewPolyRingCheck(prc.MakePoly(xnMinusC(c.n, c.c)...), modEval)

	a, b := poly(c.A), poly(c.B)
	ring.ToCommit(a.Coeffs...)
	ring.ToCommit(b.Coeffs...)

	got, err := prc.MulPolyRings(ring, a, b)
	if err != nil {
		return err
	}
	return assertCoeffs(prc.Field(), got, c.Want)
}

func TestMul(t *testing.T) {
	testMul[emulated.BN254Fp](t)
	testMul[emulated.Secp256k1Fp](t)
	testMul[emulated.BLS12377Fp](t)
}

func testMul[T emulated.FieldParams](t *testing.T) {
	var fp T
	t.Run(fmt.Sprintf("%T", fp), func(t *testing.T) {
		const n, c = 4, 2
		p := fp.Modulus()
		in := randPolys(p, 1, 2, n)
		want := refMul(p, n, big.NewInt(c), in[0], in[1])

		assignment := &mulCircuit[T]{A: elems[T](in[0]), B: elems[T](in[1]), Want: elems[T](want)}
		circuit := &mulCircuit[T]{
			A: make([]emulated.Element[T], n), B: make([]emulated.Element[T], n),
			Want: make([]emulated.Element[T], n),
			n:    n, c: c,
		}
		test.NewAssert(t).NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
	})
}

// TestMulRejectsWrongRemainder makes sure the check is not vacuous: the
// remainder the prover hands back has to be the real one.
func TestMulRejectsWrongRemainder(t *testing.T) {
	const n, c = 4, 2
	var fp emulated.BN254Fp
	p := fp.Modulus()
	in := randPolys(p, 2, 2, n)
	want := refMul(p, n, big.NewInt(c), in[0], in[1])
	want[0].Add(want[0], one).Mod(want[0], p) // off by one

	assignment := &mulCircuit[emulated.BN254Fp]{
		A: elems[emulated.BN254Fp](in[0]), B: elems[emulated.BN254Fp](in[1]),
		Want: elems[emulated.BN254Fp](want),
	}
	circuit := &mulCircuit[emulated.BN254Fp]{
		A: make([]emulated.Element[emulated.BN254Fp], n), B: make([]emulated.Element[emulated.BN254Fp], n),
		Want: make([]emulated.Element[emulated.BN254Fp], n),
		n:    n, c: c,
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Error("solved a circuit claiming the wrong remainder")
	}
}

// TestMulRejectsWrongModulusEval makes sure the deferred identity itself is
// live. The product and its remainder are honest; only the modulus evaluation
// the deferred check multiplies the folded quotient by is wrong, so nothing but
// step 4 of the protocol can catch it.
func TestMulRejectsWrongModulusEval(t *testing.T) {
	const n, c = 4, 2
	var fp emulated.BN254Fp
	p := fp.Modulus()
	in := randPolys(p, 3, 2, n)
	want := refMul(p, n, big.NewInt(c), in[0], in[1])

	assignment := &mulCircuit[emulated.BN254Fp]{
		A: elems[emulated.BN254Fp](in[0]), B: elems[emulated.BN254Fp](in[1]),
		Want: elems[emulated.BN254Fp](want),
	}
	circuit := &mulCircuit[emulated.BN254Fp]{
		A: make([]emulated.Element[emulated.BN254Fp], n), B: make([]emulated.Element[emulated.BN254Fp], n),
		Want: make([]emulated.Element[emulated.BN254Fp], n),
		n:    n, c: c,
		wrongModEval: true, // evaluates x⁴ − 3 rather than the registered x⁴ − 2
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Error("solved a circuit whose deferred identity used the wrong modulus")
	}
}

// batchCircuit claims nb independent products in one ring, so that the folded
// quotient ∑ᵢ zⁱ·qᵢ actually has something to fold.
type batchCircuit[T emulated.FieldParams] struct {
	A, B [][]emulated.Element[T]
	Want [][]emulated.Element[T]

	n, c int
}

func (c *batchCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)
	ring := prc.NewPolyRingCheck(prc.MakePoly(xnMinusC(c.n, c.c)...), nil)

	for i := range c.A {
		a, b := poly(c.A[i]), poly(c.B[i])
		ring.ToCommit(a.Coeffs...)
		ring.ToCommit(b.Coeffs...)
		got, err := prc.MulPolyRings(ring, a, b)
		if err != nil {
			return err
		}
		if err := assertCoeffs(prc.Field(), got, c.Want[i]); err != nil {
			return err
		}
	}
	return nil
}

// TestMulBatched exercises the random linear combination across many claims:
// with one claim the z-powers are all trivially 1, with eight they are not.
func TestMulBatched(t *testing.T) {
	type T = emulated.BN254Fp
	const n, c, nb = 4, 2, 8
	var fp T
	p := fp.Modulus()

	in := randPolys(p, 4, 2*nb, n)
	assignment := &batchCircuit[T]{}
	circuit := &batchCircuit[T]{n: n, c: c}
	for i := range nb {
		a, b := in[2*i], in[2*i+1]
		assignment.A = append(assignment.A, elems[T](a))
		assignment.B = append(assignment.B, elems[T](b))
		assignment.Want = append(assignment.Want, elems[T](refMul(p, n, big.NewInt(c), a, b)))
		circuit.A = append(circuit.A, make([]emulated.Element[T], n))
		circuit.B = append(circuit.B, make([]emulated.Element[T], n))
		circuit.Want = append(circuit.Want, make([]emulated.Element[T], n))
	}
	test.NewAssert(t).NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
}

// twoRingsCircuit claims a product in each of two different rings. One checker
// holds both; they share the two challenges but are batched separately, each
// against its own modulus.
type twoRingsCircuit[T emulated.FieldParams] struct {
	A1, B1, Want1 []emulated.Element[T]
	A2, B2, Want2 []emulated.Element[T]

	n1, c1, n2, c2 int
}

func (c *twoRingsCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)
	f := prc.Field()

	for _, r := range []struct {
		n, c       int
		a, b, want []emulated.Element[T]
	}{
		{c.n1, c.c1, c.A1, c.B1, c.Want1},
		{c.n2, c.c2, c.A2, c.B2, c.Want2},
	} {
		ring := prc.NewPolyRingCheck(prc.MakePoly(xnMinusC(r.n, r.c)...), nil)
		a, b := poly(r.a), poly(r.b)
		ring.ToCommit(a.Coeffs...)
		ring.ToCommit(b.Coeffs...)
		got, err := prc.MulPolyRings(ring, a, b)
		if err != nil {
			return err
		}
		if err := assertCoeffs(f, got, r.want); err != nil {
			return err
		}
	}
	return nil
}

func TestTwoRings(t *testing.T) {
	type T = emulated.BN254Fp
	const n1, c1, n2, c2 = 4, 2, 3, 5
	var fp T
	p := fp.Modulus()

	in1 := randPolys(p, 5, 2, n1)
	in2 := randPolys(p, 6, 2, n2)

	assignment := &twoRingsCircuit[T]{
		A1: elems[T](in1[0]), B1: elems[T](in1[1]), Want1: elems[T](refMul(p, n1, big.NewInt(c1), in1[0], in1[1])),
		A2: elems[T](in2[0]), B2: elems[T](in2[1]), Want2: elems[T](refMul(p, n2, big.NewInt(c2), in2[0], in2[1])),
	}
	circuit := &twoRingsCircuit[T]{
		A1: make([]emulated.Element[T], n1), B1: make([]emulated.Element[T], n1), Want1: make([]emulated.Element[T], n1),
		A2: make([]emulated.Element[T], n2), B2: make([]emulated.Element[T], n2), Want2: make([]emulated.Element[T], n2),
		n1: n1, c1: c1, n2: n2, c2: c2,
	}
	test.NewAssert(t).NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
}

// accumulatorCircuit multiplies three factors through [PolyRingAccumulator],
// with a target degree low enough that the queue has to collapse partway.
type accumulatorCircuit[T emulated.FieldParams] struct {
	A, B, C, Want []emulated.Element[T]

	n, c, targetDeg int
}

func (c *accumulatorCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)
	ring := prc.NewPolyRingCheck(prc.MakePoly(xnMinusC(c.n, c.c)...), nil)

	acc := prc.NewPolyRingAccumulator(ring, c.targetDeg)
	for _, els := range [][]emulated.Element[T]{c.A, c.B, c.C} {
		p := poly(els)
		ring.ToCommit(p.Coeffs...)
		acc.Mul(p)
	}
	return assertCoeffs(prc.Field(), acc.Eval(), c.Want)
}

func TestAccumulator(t *testing.T) {
	type T = emulated.BN254Fp
	const n, c = 4, 2
	var fp T
	p := fp.Modulus()
	in := randPolys(p, 7, 3, n)
	want := refMul(p, n, big.NewInt(c), in[0], in[1], in[2])

	// targetDeg 6 is below the degree of all three factors together, so the
	// accumulator collapses after the second and claims two products in all;
	// targetDeg 0 queues everything and claims one.
	for _, targetDeg := range []int{0, 6} {
		t.Run(fmt.Sprintf("targetDeg=%d", targetDeg), func(t *testing.T) {
			assignment := &accumulatorCircuit[T]{
				A: elems[T](in[0]), B: elems[T](in[1]), C: elems[T](in[2]), Want: elems[T](want),
			}
			circuit := &accumulatorCircuit[T]{
				A: make([]emulated.Element[T], n), B: make([]emulated.Element[T], n),
				C: make([]emulated.Element[T], n), Want: make([]emulated.Element[T], n),
				n: n, c: c, targetDeg: targetDeg,
			}
			test.NewAssert(t).NoError(test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()))
		})
	}
}

// nativeToEmulatedCircuit carries a native variable across into the emulated
// field, the way the deferred check carries the two challenges across.
type nativeToEmulatedCircuit[T emulated.FieldParams] struct {
	X    frontend.Variable
	Want emulated.Element[T]
}

func (c *nativeToEmulatedCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)
	got, err := prc.NativeToEmulated(c.X)
	if err != nil {
		return err
	}
	prc.Field().AssertIsEqual(got[0], &c.Want)
	return nil
}

// TestNativeToEmulated checks the challenge crosses fields intact, for emulated
// fields both narrower and wider in limbs than the native one.
func TestNativeToEmulated(t *testing.T) {
	x, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	for _, tc := range []struct {
		name   string
		solved func(*testing.T) error
	}{
		{"BN254Fp", func(*testing.T) error {
			type T = emulated.BN254Fp
			return test.IsSolved(&nativeToEmulatedCircuit[T]{},
				&nativeToEmulatedCircuit[T]{X: x, Want: emulated.ValueOf[T](x)}, ecc.BN254.ScalarField())
		}},
		{"BLS12377Fp", func(*testing.T) error {
			type T = emulated.BLS12377Fp
			return test.IsSolved(&nativeToEmulatedCircuit[T]{},
				&nativeToEmulatedCircuit[T]{X: x, Want: emulated.ValueOf[T](x)}, ecc.BN254.ScalarField())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test.NewAssert(t).NoError(tc.solved(t))
		})
	}
}
