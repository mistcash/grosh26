package polyring

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// testMod is w¹² - 2w⁶ + 2, the BLS12-381 𝔽p¹² modulus; any monic modulus
// would do.
var testMod = []any{2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0, 1}

// ringMulCircuit claims AB = A·B and ABC = (A·B)·C = A·B·C in the ring, as
// three deferred checks of one group: with more than one check, the quotient
// RLC hint's view of the challenge z has to agree with the in-circuit one.
type ringMulCircuit[T emulated.FieldParams] struct {
	A, B, C [12]emulated.Element[T]
	AB, ABC [12]emulated.Element[T]
}

func (c *ringMulCircuit[T]) Define(api frontend.API) error {
	prc := NewPolyRingChecker[T](api)
	f := prc.Field()
	group := prc.NewPolyRingCheck(prc.MakePoly(testMod...), nil)

	toPoly := func(v *[12]emulated.Element[T]) *Poly[T] {
		p := &Poly[T]{Coeffs: make([]*emulated.Element[T], 12)}
		for i := range v {
			p.Coeffs[i] = &v[i]
		}
		// witness operands are committed, see [PolyRingGroupChecks.ToCommit]
		group.ToCommit(p.Coeffs...)
		return p
	}
	a, b, cc := toPoly(&c.A), toPoly(&c.B), toPoly(&c.C)

	ab, err := prc.MulPolyRings(group, a, b)
	if err != nil {
		return err
	}
	// ab is a remainder, committed by the deferred check itself
	abc, err := prc.MulPolyRings(group, ab, cc)
	if err != nil {
		return err
	}
	abc2, err := prc.MulPolyRings(group, a, b, cc)
	if err != nil {
		return err
	}
	for i := range 12 {
		f.AssertIsEqual(ab.Coeffs[i], &c.AB[i])
		f.AssertIsEqual(abc.Coeffs[i], &c.ABC[i])
		f.AssertIsEqual(abc2.Coeffs[i], &c.ABC[i])
	}
	return nil
}

func randomPoly(t *testing.T, p *big.Int) []*big.Int {
	t.Helper()
	res := make([]*big.Int, 12)
	for i := range res {
		var err error
		if res[i], err = rand.Int(rand.Reader, p); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

func ringMul(t *testing.T, p *big.Int, inputs ...[]*big.Int) []*big.Int {
	t.Helper()
	mod := make([]*big.Int, len(testMod))
	for i, c := range testMod {
		mod[i] = new(big.Int).Mod(big.NewInt(int64(c.(int))), p)
	}
	_, r, err := polyRingMul(p, inputs, mod)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assign[T emulated.FieldParams](v []*big.Int) (res [12]emulated.Element[T]) {
	for i := range res {
		res[i] = emulated.ValueOf[T](v[i])
	}
	return res
}

// TestRingMul runs the deferred ring check over BN254's base field, whose
// limbs the native challenge fills exactly, and over BLS12-381's, which has
// more limbs than the challenge and so gets it zero-padded.
func TestRingMul(t *testing.T) {
	t.Run("bn254-fp", testRingMul[emparams.BN254Fp])
	t.Run("bls12-381-fp", testRingMul[emparams.BLS12381Fp])
}

func testRingMul[T emulated.FieldParams](t *testing.T) {
	var fp T
	p := fp.Modulus()
	a, b, c := randomPoly(t, p), randomPoly(t, p), randomPoly(t, p)
	ab := ringMul(t, p, a, b)
	abc := ringMul(t, p, ab, c)

	assignment := &ringMulCircuit[T]{
		A: assign[T](a), B: assign[T](b), C: assign[T](c),
		AB: assign[T](ab), ABC: assign[T](abc),
	}
	// a wrong claimed product is rejected
	bad := *assignment
	bad.ABC[3] = emulated.ValueOf[T](new(big.Int).Add(abc[3], big.NewInt(1)))

	// beyond the test engine, this solves the compiled R1CS and PLONK
	// systems, where the nested commitments are real; -tags=prover_checks
	// proves them too
	test.NewAssert(t).CheckCircuit(&ringMulCircuit[T]{},
		test.WithValidAssignment(assignment), test.WithInvalidAssignment(&bad),
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16, backend.PLONK))
}
