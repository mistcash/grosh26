// Package ringpairing checks pairings inside gnark circuits with 𝔽p¹²
// arithmetic evaluated in the polynomial ring 𝔽p[w]/(w¹² - 2ξ₀w⁶ + ξ₀² + 1)
// instead of reducing every product on the spot, following
// [On Proving Pairings].
//
// This package is the curve-agnostic core: the ring, the Miller loop driver
// and the residue witness check. Everything curve-specific -- the twist and
// its G2 ladder, the line shape, the loop counter, gnark's types and hints --
// lives behind [Curve], implemented by std/ring_bn254 and std/ring_bls12381,
// which also provide the constructors.
//
// Everything about 𝔽p¹² itself -- the element types, the Frobenius maps, the
// tower conversions, the residue witness hints -- comes from gnark, which
// already represents E12 as this direct extension. What this package adds is
// the ring: a product is claimed through a hint and its correctness deferred,
// so a whole circuit's worth of claims collapses into one identity checked at
// a random point.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
package ringpairing

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/grosh26/std/polyring"
)

type poly[F emulated.FieldParams] = polyring.Poly[F]

// ring is 𝔽p¹² as 𝔽p[w]/(w¹² - 2ξ₀w⁶ + ξ₀² + 1), for a curve building 𝔽p¹²
// as 𝔽p²[w]/(w⁶ - ξ) with 𝔽p² = 𝔽p[u]/(u² + 1) and ξ = ξ₀ + u: then
// u = w⁶ - ξ₀, and (w⁶ - ξ₀)² = -1 gives the modulus. A curve with another
// 𝔽p² would need its own modulus here.
type ring[F emulated.FieldParams] struct {
	fp    *emulated.Field[F]
	prc   *polyring.PolyRingChecker[F]
	group *polyring.PolyRingGroupChecks[F]
	xi0   int64
	// inverseHint is gnark's 𝔽p¹² inverse hint for the curve; it reads the
	// direct-extension coefficients.
	inverseHint solver.Hint
}

// newRing adds the ring group for ξ₀ to prc, whose deferred checks run once
// Define returns. prc has to be created before anything else in the circuit
// creates an emulated field, see [New].
func newRing[F emulated.FieldParams](prc *polyring.PolyRingChecker[F], xi0 int64, inverseHint solver.Hint) *ring[F] {
	fp := prc.Field()
	c0, c6 := xi0*xi0+1, -2*xi0

	// only three coefficients of the modulus are non-zero, so evaluating it at
	// the challenge is cheaper as a closure than as the generic inner product
	modEval := func(xPowers []*emulated.Element[F]) *emulated.Element[F] {
		return fp.Add(
			fp.MulConst(xPowers[0], big.NewInt(c0)),
			fp.Add(fp.MulConst(xPowers[6], big.NewInt(c6)), xPowers[12]),
		)
	}
	mod := prc.MakePoly(c0, 0, 0, 0, 0, 0, c6, 0, 0, 0, 0, 0, 1)

	return &ring[F]{
		fp:          fp,
		prc:         prc,
		group:       prc.NewPolyRingCheck(mod, modEval),
		xi0:         xi0,
		inverseHint: inverseHint,
	}
}

// commit adds elements to the values the Schwartz-Zippel challenge is drawn
// from. Every ring-check operand the prover chooses -- circuit inputs and
// hinted values alike -- has to be fixed before the draw, either directly or
// as a fully constrained function of committed values. Constants are skipped.
func (r *ring[F]) commit(elements ...*emulated.Element[F]) {
	r.group.ToCommit(elements...)
}

// commitPoly commits a polynomial's coefficients, see [ring.commit].
func (r *ring[F]) commitPoly(polys ...*poly[F]) {
	for _, p := range polys {
		r.commit(p.Coeffs...)
	}
}

// accumulator returns an accumulator queueing products in this ring,
// collapsing them into one deferred check whenever targetDeg would be exceeded.
func (r *ring[F]) accumulator(targetDeg int) *polyring.PolyRingAccumulator[F] {
	return r.prc.NewPolyRingAccumulator(r.group, targetDeg)
}

// mul multiplies polynomials in the ring as a single deferred check. The
// operands must already be committed to, see [ring.commit].
func (r *ring[F]) mul(inputs ...*poly[F]) *poly[F] {
	rem, err := r.prc.MulPolyRings(r.group, inputs...)
	if err != nil {
		panic(err)
	}
	return rem
}

// inverse returns x⁻¹, hinted and then constrained by a single ring product.
// x and the hinted inverse are both committed: they are operands of that
// product. A zero x has no inverse, so the hint fails.
func (r *ring[F]) inverse(x *poly[F]) *poly[F] {
	inv, err := r.fp.NewHint(r.inverseHint, 12, x.Coeffs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	invPoly := &poly[F]{Coeffs: inv}
	r.commitPoly(x, invPoly)
	r.assertIsOne(r.mul(x, invPoly))
	return invPoly
}

// assertIsOne asserts a 12-coefficient polynomial is the constant 1.
func (r *ring[F]) assertIsOne(x *poly[F]) {
	r.fp.AssertIsEqual(x.Coeffs[0], r.fp.One())
	for _, c := range x.Coeffs[1:] {
		r.fp.AssertIsEqual(c, r.fp.Zero())
	}
}

// embedE2 writes the 𝔽p² element a0 + a1·u into coeffs as a w^at term:
// u = w⁶ - ξ₀, so it is (a0 - ξ₀·a1)·w^at + a1·w^(at+6).
func (r *ring[F]) embedE2(coeffs []*emulated.Element[F], at int, a0, a1 *emulated.Element[F]) {
	coeffs[at] = r.fp.Sub(a0, r.fp.MulConst(a1, big.NewInt(r.xi0)))
	coeffs[at+6] = a1
}

// fp6 returns the 𝔽p⁶ element with tower coefficients c (three 𝔽p² elements,
// as gnark's residue witness hints return the scaling factor) as a ring
// polynomial: the 𝔽p² parts land on w⁰, w² and w⁴, every odd power is zero.
func (r *ring[F]) fp6(c []*emulated.Element[F]) *poly[F] {
	coeffs := make([]*emulated.Element[F], 12)
	for i := range coeffs {
		coeffs[i] = r.fp.Zero()
	}
	for i := 0; i < 3; i++ {
		r.embedE2(coeffs, 2*i, c[2*i], c[2*i+1])
	}
	return &poly[F]{Coeffs: coeffs}
}
