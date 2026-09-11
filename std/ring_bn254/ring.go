// Package ring_bn254 evaluates BN254 𝔽p¹² arithmetic in the polynomial ring
// 𝔽p[x]/(x¹² - 18x⁶ + 82) instead of reducing every product on the spot.
//
// Everything about 𝔽p¹² itself -- the element type, the coefficient-wise
// operations, the Frobenius maps, the tower conversions -- comes from gnark's
// [fields_bn254], which already represents E12 as the direct extension. What
// this package adds is the ring: a product is claimed through a hint and its
// correctness deferred, so a whole circuit's worth of claims collapses into one
// identity checked at a random point.
package ring_bn254

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/polyring"
)

type (
	baseEl   = emulated.Element[emulated.BN254Fp]
	basePoly = polyring.Poly[emulated.BN254Fp]
	curveF   = emulated.Field[emulated.BN254Fp]
)

// E12 is gnark's 𝔽p¹² element, unchanged.
type E12 = fields_bn254.E12

// Ext12 is gnark's 𝔽p¹² arithmetic with the polynomial ring bolted on.
// Everything gnark provides is reachable through the embedded [fields_bn254.Ext12];
// the methods here are the ones that go through the ring.
type Ext12 struct {
	*fields_bn254.Ext12
	fp   *curveF
	prc  *polyring.PolyRingChecker[emulated.BN254Fp]
	ring *polyring.PolyRingGroupChecks[emulated.BN254Fp]
}

// NewExt12 registers the ring group for x¹² - 18x⁶ + 82 with the compiler. The
// deferred checks run once Define returns.
//
// Call this before anything else in the circuit creates an emulated field: the
// ring checks emit range checks of their own, and gnark runs deferred callbacks
// in registration order, so the range checker -- created with the first
// emulated field -- has to be registered after the ring checker or it will
// already be closed by the time the ring checks run.
func NewExt12(api frontend.API) *Ext12 {
	prc := polyring.NewPolyRingChecker[emulated.BN254Fp](api)
	fp := prc.Field()

	// only three coefficients of the modulus are non-zero, so evaluating it at
	// the challenge is cheaper as a closure than as the generic inner product
	modEval := func(xPowers []*baseEl) *baseEl {
		return fp.Add(
			fp.MulConst(xPowers[0], big.NewInt(82)),
			fp.Add(fp.MulConst(xPowers[6], big.NewInt(-18)), xPowers[12]),
		)
	}

	return &Ext12{
		Ext12: fields_bn254.NewExt12(api),
		fp:    fp,
		prc:   prc,
		ring:  prc.NewPolyRingCheck(prc.MakePoly(82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0, 1), modEval),
	}
}

// ToPoly views an 𝔽p¹² element as a polynomial over the emulated field.
func (e Ext12) ToPoly(a *E12) *basePoly {
	return &basePoly{Coeffs: []*baseEl{
		&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5,
		&a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11,
	}}
}

// PolyToE12 is the inverse of [Ext12.ToPoly].
func (e Ext12) PolyToE12(p *basePoly) *E12 {
	if len(p.Coeffs) != 12 {
		panic("ring_bn254: expected 12 coefficients")
	}
	c := p.Coeffs
	return &E12{
		A0: *c[0], A1: *c[1], A2: *c[2], A3: *c[3], A4: *c[4], A5: *c[5],
		A6: *c[6], A7: *c[7], A8: *c[8], A9: *c[9], A10: *c[10], A11: *c[11],
	}
}

// ToCommit adds polynomial coefficients to the values the Schwartz-Zippel
// challenge is drawn from. Every ring-check operand the prover chooses --
// circuit inputs and hinted values alike -- has to be fixed before the draw.
func (e Ext12) ToCommit(polys ...*basePoly) {
	for _, p := range polys {
		e.ring.ToCommit(p.Coeffs...)
	}
}

// NewAccumulator returns an accumulator queueing products in this ring,
// collapsing them into one deferred check whenever targetDeg would be exceeded.
func (e Ext12) NewAccumulator(targetDeg int) *polyring.PolyRingAccumulator[emulated.BN254Fp] {
	return e.prc.NewPolyRingAccumulator(e.ring, targetDeg)
}

// MulPoly multiplies polynomials in the ring as a single deferred check. The
// operands must already be committed to, see [Ext12.ToCommit].
func (e Ext12) MulPoly(inputs ...*basePoly) *basePoly {
	rem, err := e.prc.MulPolyRings(e.ring, inputs...)
	if err != nil {
		panic(err)
	}
	return rem
}

// Mul multiplies in the ring rather than coefficient-wise. It shadows
// [fields_bn254.Ext12.Mul], which stays reachable as e.Ext12.Mul.
func (e Ext12) Mul(x, y *E12) *E12 {
	xp, yp := e.ToPoly(x), e.ToPoly(y)
	e.ToCommit(xp, yp)
	return e.PolyToE12(e.MulPoly(xp, yp))
}

// Square squares in the ring. It shadows [fields_bn254.Ext12.Square].
func (e Ext12) Square(x *E12) *E12 {
	xp := e.ToPoly(x)
	e.ToCommit(xp)
	return e.PolyToE12(e.MulPoly(xp, xp))
}

// InversePoly returns the inverse of x, hinted and then constrained by a single
// ring product. The hinted inverse is an operand of that product, so it is
// committed to before the challenge is drawn.
func (e Ext12) InversePoly(x *basePoly) *basePoly {
	c := x.Coeffs
	res, err := e.fp.NewHint(inverseE12Hint, 12, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	inv := &basePoly{Coeffs: res}

	e.ToCommit(x, inv)
	e.AssertIsEqual(e.PolyToE12(e.MulPoly(x, inv)), e.One())

	return inv
}

// Inverse returns x⁻¹, constrained by one ring product. It shadows
// [fields_bn254.Ext12.Inverse].
func (e Ext12) Inverse(x *E12) *E12 {
	return e.PolyToE12(e.InversePoly(e.ToPoly(x)))
}

// ToPoly01379 views a sparse 𝔽p¹² line evaluation as a degree-9 polynomial:
//
//	b.A0 = 1, b.A1 = c3.A0 - 9*c3.A1, b.A3 = c4.A0 - 9*c4.A1,
//	b.A7 = c3.A1, b.A9 = c4.A1, and the rest zero.
//
// Feeding lines to the ring in this form is what lets the Miller loop batch
// them as plain products, instead of gnark's sparse multiplication routines.
func (e Ext12) ToPoly01379(c3, c4 *fields_bn254.E2) *basePoly {
	nine := big.NewInt(9)
	return &basePoly{Coeffs: []*baseEl{
		e.fp.One(),
		e.fp.Sub(&c3.A0, e.fp.MulConst(&c3.A1, nine)),
		nil,
		e.fp.Sub(&c4.A0, e.fp.MulConst(&c4.A1, nine)),
		nil, nil, nil,
		&c3.A1,
		nil,
		&c4.A1,
	}}
}
