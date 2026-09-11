package polyring_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/polyring"
)

type Fp = emulated.BN254Fp

// exampleCircuit multiplies two elements of 𝔽p[x]/(x⁴ − 2). It is the snippet
// in the README, kept here so the compiler checks it.
type exampleCircuit struct {
	A, B [4]emulated.Element[Fp]
}

func (c *exampleCircuit) Define(api frontend.API) error {
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

var _ frontend.Circuit = (*exampleCircuit)(nil)
