package fields_bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fp_bn "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	polyring "github.com/mistcash/grosh26"
)

// accumulatorTargetDegree caps the degree of a product queued in a
// [polyring.PolyRingAccumulator] before it is collapsed into a single ring
// check. An 𝔽p¹² element is a degree-11 polynomial, so 33 batches three
// factors per check: the quotient of the Euclidean division then has degree
// 33-12 = 21, and one deferred check replaces two.
const accumulatorTargetDegree = 33

// E12 is an element of 𝔽p¹² = 𝔽p[x]/(x¹² - 18x⁶ + 82), held as the twelve
// coefficients A0..A11 of its polynomial representation.
type E12 struct {
	A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11 baseEl
	poly                                             *basePoly
}

// Ext12 is the 𝔽p¹² arithmetic context. Multiplications are deferred ring
// product checks registered on ring, which the polynomial ring checker batches
// and verifies once, at a random point, after Define returns.
type Ext12 struct {
	*Ext2
	api  frontend.API
	fp   *curveF
	prc  *polyring.PolyRingChecker[emulated.BN254Fp]
	ring *polyring.PolyRingGroupChecks[emulated.BN254Fp]
}

// NewExt12 returns an 𝔽p¹² arithmetic context. It registers a polynomial ring
// group for the modulus x¹² - 18x⁶ + 82 with the compiler; the deferred checks
// run when the circuit's Define has completed.
func NewExt12(api frontend.API) *Ext12 {
	prc := polyring.NewPolyRingChecker[emulated.BN254Fp](api)
	fp := prc.Field()

	// direct 𝔽p¹² extension: 𝔽p[x]/(x¹² - 18x⁶ + 82)
	modPoly := prc.MakePoly(82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0, 1)
	// evaluating the modulus at the challenge only needs the three non-zero
	// coefficients, so give the checker a closure instead of the generic
	// inner product over all thirteen.
	modEval := func(xPowers []*baseEl) *baseEl {
		a0 := fp.MulConst(xPowers[0], big.NewInt(82))
		a6 := fp.MulConst(xPowers[6], big.NewInt(-18))
		a12 := xPowers[12]
		return fp.Add(a0, fp.Add(a6, a12))
	}

	return &Ext12{
		Ext2: newExt2(api, fp),
		api:  api,
		fp:   fp,
		prc:  prc,
		ring: prc.NewPolyRingCheck(modPoly, modEval),
	}
}

// ToPoly views the element as a polynomial over the emulated field. The view is
// cached on the element so that repeated ring checks over the same operand
// share its evaluation at the verifier challenge.
func (a *E12) ToPoly() *basePoly {
	if a.poly == nil {
		a.poly = &basePoly{
			Coeffs: []*baseEl{
				&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5,
				&a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11,
			},
		}
	}
	return a.poly
}

func (e Ext12) ToPoly(a *E12) *basePoly {
	return a.ToPoly()
}

func (e Ext12) PolyToE12(p *basePoly) *E12 {
	if len(p.Coeffs) != 12 {
		panic("invalid number of coefficients for E12")
	}
	return &E12{
		A0:   *p.Coeffs[0],
		A1:   *p.Coeffs[1],
		A2:   *p.Coeffs[2],
		A3:   *p.Coeffs[3],
		A4:   *p.Coeffs[4],
		A5:   *p.Coeffs[5],
		A6:   *p.Coeffs[6],
		A7:   *p.Coeffs[7],
		A8:   *p.Coeffs[8],
		A9:   *p.Coeffs[9],
		A10:  *p.Coeffs[10],
		A11:  *p.Coeffs[11],
		poly: p,
	}
}

// FromPoly is an alias for PolyToE12.
func (e Ext12) FromPoly(p *basePoly) *E12 {
	return e.PolyToE12(p)
}

// PolyRingChecker returns the ring group all 𝔽p¹² products are checked against.
func (e Ext12) PolyRingChecker() *polyring.PolyRingGroupChecks[emulated.BN254Fp] {
	return e.ring
}

// NewPolyRingAccumulator returns an accumulator queueing products in this ring.
func (e Ext12) NewPolyRingAccumulator(targetDeg int) *polyring.PolyRingAccumulator[emulated.BN254Fp] {
	return e.prc.NewPolyRingAccumulator(e.ring, targetDeg)
}

// MulPoly multiplies the given polynomials in the ring, as a single deferred
// check. The inputs must already be committed to, see [Ext12.ToCommit].
func (e Ext12) MulPoly(inputs ...*basePoly) *basePoly {
	rem, err := e.prc.MulPolyRings(e.ring, inputs...)
	if err != nil {
		panic(err)
	}
	return rem
}

// ToCommit adds the coefficients of the given polynomials to the values the
// Schwartz-Zippel challenge is derived from. Every operand of a ring check the
// prover is free to choose -- circuit inputs and hinted values alike -- has to
// be fixed before the challenge is drawn.
func (e Ext12) ToCommit(polys ...*basePoly) {
	for _, p := range polys {
		e.ring.ToCommit(p.Coeffs...)
	}
}

func (e Ext12) Zero() *E12 {
	zero := e.fp.Zero()
	return &E12{
		A0:  *zero,
		A1:  *zero,
		A2:  *zero,
		A3:  *zero,
		A4:  *zero,
		A5:  *zero,
		A6:  *zero,
		A7:  *zero,
		A8:  *zero,
		A9:  *zero,
		A10: *zero,
		A11: *zero,
	}
}

func (e Ext12) One() *E12 {
	one := e.fp.One()
	zero := e.fp.Zero()
	return &E12{
		A0:  *one,
		A1:  *zero,
		A2:  *zero,
		A3:  *zero,
		A4:  *zero,
		A5:  *zero,
		A6:  *zero,
		A7:  *zero,
		A8:  *zero,
		A9:  *zero,
		A10: *zero,
		A11: *zero,
	}
}

func (e Ext12) Neg(x *E12) *E12 {
	return &E12{
		A0:  *e.fp.Neg(&x.A0),
		A1:  *e.fp.Neg(&x.A1),
		A2:  *e.fp.Neg(&x.A2),
		A3:  *e.fp.Neg(&x.A3),
		A4:  *e.fp.Neg(&x.A4),
		A5:  *e.fp.Neg(&x.A5),
		A6:  *e.fp.Neg(&x.A6),
		A7:  *e.fp.Neg(&x.A7),
		A8:  *e.fp.Neg(&x.A8),
		A9:  *e.fp.Neg(&x.A9),
		A10: *e.fp.Neg(&x.A10),
		A11: *e.fp.Neg(&x.A11),
	}
}

func (e Ext12) Add(x, y *E12) *E12 {
	return &E12{
		A0:  *e.fp.Add(&x.A0, &y.A0),
		A1:  *e.fp.Add(&x.A1, &y.A1),
		A2:  *e.fp.Add(&x.A2, &y.A2),
		A3:  *e.fp.Add(&x.A3, &y.A3),
		A4:  *e.fp.Add(&x.A4, &y.A4),
		A5:  *e.fp.Add(&x.A5, &y.A5),
		A6:  *e.fp.Add(&x.A6, &y.A6),
		A7:  *e.fp.Add(&x.A7, &y.A7),
		A8:  *e.fp.Add(&x.A8, &y.A8),
		A9:  *e.fp.Add(&x.A9, &y.A9),
		A10: *e.fp.Add(&x.A10, &y.A10),
		A11: *e.fp.Add(&x.A11, &y.A11),
	}
}

func (e Ext12) Sub(x, y *E12) *E12 {
	return &E12{
		A0:  *e.fp.Sub(&x.A0, &y.A0),
		A1:  *e.fp.Sub(&x.A1, &y.A1),
		A2:  *e.fp.Sub(&x.A2, &y.A2),
		A3:  *e.fp.Sub(&x.A3, &y.A3),
		A4:  *e.fp.Sub(&x.A4, &y.A4),
		A5:  *e.fp.Sub(&x.A5, &y.A5),
		A6:  *e.fp.Sub(&x.A6, &y.A6),
		A7:  *e.fp.Sub(&x.A7, &y.A7),
		A8:  *e.fp.Sub(&x.A8, &y.A8),
		A9:  *e.fp.Sub(&x.A9, &y.A9),
		A10: *e.fp.Sub(&x.A10, &y.A10),
		A11: *e.fp.Sub(&x.A11, &y.A11),
	}
}

func (e Ext12) Double(x *E12) *E12 {
	two := big.NewInt(2)
	return &E12{
		A0:  *e.fp.MulConst(&x.A0, two),
		A1:  *e.fp.MulConst(&x.A1, two),
		A2:  *e.fp.MulConst(&x.A2, two),
		A3:  *e.fp.MulConst(&x.A3, two),
		A4:  *e.fp.MulConst(&x.A4, two),
		A5:  *e.fp.MulConst(&x.A5, two),
		A6:  *e.fp.MulConst(&x.A6, two),
		A7:  *e.fp.MulConst(&x.A7, two),
		A8:  *e.fp.MulConst(&x.A8, two),
		A9:  *e.fp.MulConst(&x.A9, two),
		A10: *e.fp.MulConst(&x.A10, two),
		A11: *e.fp.MulConst(&x.A11, two),
	}
}

func (e Ext12) Conjugate(x *E12) *E12 {
	return &E12{
		A0:  x.A0,
		A1:  *e.fp.Neg(&x.A1),
		A2:  x.A2,
		A3:  *e.fp.Neg(&x.A3),
		A4:  x.A4,
		A5:  *e.fp.Neg(&x.A5),
		A6:  x.A6,
		A7:  *e.fp.Neg(&x.A7),
		A8:  x.A8,
		A9:  *e.fp.Neg(&x.A9),
		A10: x.A10,
		A11: *e.fp.Neg(&x.A11),
	}
}

// Mul multiplies in the polynomial ring: the product and its quotient come from
// a hint and the identity x*y = r + q*(x¹² - 18x⁶ + 82) is checked later,
// batched with every other ring check of the circuit.
func (e Ext12) Mul(x, y *E12) *E12 {
	xPoly := x.ToPoly()
	yPoly := y.ToPoly()
	e.ToCommit(xPoly, yPoly)
	return e.PolyToE12(e.MulPoly(xPoly, yPoly))
}

// Square squares in the polynomial ring, as a single deferred check.
func (e Ext12) Square(x *E12) *E12 {
	xPoly := x.ToPoly()
	e.ToCommit(xPoly)
	return e.PolyToE12(e.MulPoly(xPoly, xPoly))
}

// ExpConst returns x^exp for an exponent known at compile time, by
// square-and-multiply. Factors are queued in a ring accumulator, so up to three
// of them collapse into one deferred check instead of one check per step.
func (e Ext12) ExpConst(x *E12, exp *big.Int) *E12 {
	if exp.Sign() < 0 {
		panic("ExpConst: negative exponent")
	}
	if exp.Sign() == 0 {
		return e.One()
	}

	xPoly := x.ToPoly()
	e.ToCommit(xPoly)

	acc := e.NewPolyRingAccumulator(accumulatorTargetDegree)
	// the leading bit of exp is always 1, so start the square-and-multiply at x
	acc.Mul(xPoly)
	for i := exp.BitLen() - 2; i >= 0; i-- {
		acc.Sqr()
		if exp.Bit(i) == 1 {
			acc.Mul(xPoly)
		}
	}
	return e.PolyToE12(acc.Eval())
}

// MulDirect multiplies coefficient-wise, without the ring: every coefficient of
// the product is one [emulated.Field.Eval] over the reduced cross terms. Kept
// for comparison against [Ext12.Mul].
func (e Ext12) MulDirect(a, b *E12) *E12 {

	// a = a11 w^11 + a10 w^10 + a9 w^9 + a8 w^8 + a7 w^7 + a6 w^6 + a5 w^5 + a4 w^4 + a3 w^3 + a2 w^2 + a1 w + a0
	// b = b11 w^11 + b10 w^10 + b9 w^9 + b8 w^8 + b7 w^7 + b6 w^6 + b5 w^5 + b4 w^4 + b3 w^3 + b2 w^2 + b1 w + b0
	//
	// Given that w^12 = 18 w^6 - 82, we can compute the product a * b as follows:
	//
	// a * b = d11 w^11 + d10 w^10 + d9 w^9 + d8 w^8 + d7 w^7 + d6 w^6 + d5 w^5 + d4 w^4 + d3 w^3 + d2 w^2 + d1 w + d0
	//
	// where:
	//
	// d0  =  c0  - 82 * c12 - 1476 * c18
	// d1  =  c1  - 82 * c13 - 1476 * c19
	// d2  =  c2  - 82 * c14 - 1476 * c20
	// d3  =  c3  - 82 * c15 - 1476 * c21
	// d4  =  c4  - 82 * c16 - 1476 * c22
	// d5  =  c5  - 82 * c17
	// d6  =  c6  + 18 * c12 + 242 * c18
	// d7  =  c7  + 18 * c13 + 242 * c19
	// d8  =  c8  + 18 * c14 + 242 * c20
	// d9  =  c9  + 18 * c15 + 242 * c21
	// d10 =  c10 + 18 * c16 + 242 * c22
	// d11 =  c11 + 18 * c17
	//
	// and c_k is the k-th coefficient of the unreduced product,
	// c_k = ∑_{i+j=k} a_i b_j.

	// d0  =  c0  - 82 * c12 - 1476 * c18
	d0 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A0}, {&a.A1, &b.A11}, {&a.A2, &b.A10}, {&a.A3, &b.A9}, {&a.A4, &b.A8}, {&a.A5, &b.A7}, {&a.A6, &b.A6}, {&a.A7, &b.A5}, {&a.A8, &b.A4}, {&a.A9, &b.A3}, {&a.A10, &b.A2}, {&a.A11, &b.A1}, {&a.A7, &b.A11}, {&a.A8, &b.A10}, {&a.A9, &b.A9}, {&a.A10, &b.A8}, {&a.A11, &b.A7}}, []int{1, -82, -82, -82, -82, -82, -82, -82, -82, -82, -82, -82, -1476, -1476, -1476, -1476, -1476})

	// d1  =  c1  - 82 * c13 - 1476 * c19
	d1 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A1}, {&a.A1, &b.A0}, {&a.A2, &b.A11}, {&a.A3, &b.A10}, {&a.A4, &b.A9}, {&a.A5, &b.A8}, {&a.A6, &b.A7}, {&a.A7, &b.A6}, {&a.A8, &b.A5}, {&a.A9, &b.A4}, {&a.A10, &b.A3}, {&a.A11, &b.A2}, {&a.A8, &b.A11}, {&a.A9, &b.A10}, {&a.A10, &b.A9}, {&a.A11, &b.A8}}, []int{1, 1, -82, -82, -82, -82, -82, -82, -82, -82, -82, -82, -1476, -1476, -1476, -1476})

	// d2  =  c2  - 82 * c14 - 1476 * c20
	d2 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A2}, {&a.A1, &b.A1}, {&a.A2, &b.A0}, {&a.A3, &b.A11}, {&a.A4, &b.A10}, {&a.A5, &b.A9}, {&a.A6, &b.A8}, {&a.A7, &b.A7}, {&a.A8, &b.A6}, {&a.A9, &b.A5}, {&a.A10, &b.A4}, {&a.A11, &b.A3}, {&a.A9, &b.A11}, {&a.A10, &b.A10}, {&a.A11, &b.A9}}, []int{1, 1, 1, -82, -82, -82, -82, -82, -82, -82, -82, -82, -1476, -1476, -1476})

	// d3  =  c3  - 82 * c15 - 1476 * c21
	d3 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A3}, {&a.A1, &b.A2}, {&a.A2, &b.A1}, {&a.A3, &b.A0}, {&a.A4, &b.A11}, {&a.A5, &b.A10}, {&a.A6, &b.A9}, {&a.A7, &b.A8}, {&a.A8, &b.A7}, {&a.A9, &b.A6}, {&a.A10, &b.A5}, {&a.A11, &b.A4}, {&a.A10, &b.A11}, {&a.A11, &b.A10}}, []int{1, 1, 1, 1, -82, -82, -82, -82, -82, -82, -82, -82, -1476, -1476})

	// d4  =  c4  - 82 * c16 - 1476 * c22
	d4 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A4}, {&a.A1, &b.A3}, {&a.A2, &b.A2}, {&a.A3, &b.A1}, {&a.A4, &b.A0}, {&a.A5, &b.A11}, {&a.A6, &b.A10}, {&a.A7, &b.A9}, {&a.A8, &b.A8}, {&a.A9, &b.A7}, {&a.A10, &b.A6}, {&a.A11, &b.A5}, {&a.A11, &b.A11}}, []int{1, 1, 1, 1, 1, -82, -82, -82, -82, -82, -82, -82, -1476})

	// d5  =  c5  - 82 * c17
	d5 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A5}, {&a.A1, &b.A4}, {&a.A2, &b.A3}, {&a.A3, &b.A2}, {&a.A4, &b.A1}, {&a.A5, &b.A0}, {&a.A6, &b.A11}, {&a.A7, &b.A10}, {&a.A8, &b.A9}, {&a.A9, &b.A8}, {&a.A10, &b.A7}, {&a.A11, &b.A6}}, []int{1, 1, 1, 1, 1, 1, -82, -82, -82, -82, -82, -82})

	// d6  =  c6  + 18 * c12 + 242 * c18
	d6 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A6}, {&a.A1, &b.A5}, {&a.A2, &b.A4}, {&a.A3, &b.A3}, {&a.A4, &b.A2}, {&a.A5, &b.A1}, {&a.A6, &b.A0}, {&a.A1, &b.A11}, {&a.A2, &b.A10}, {&a.A3, &b.A9}, {&a.A4, &b.A8}, {&a.A5, &b.A7}, {&a.A6, &b.A6}, {&a.A7, &b.A5}, {&a.A8, &b.A4}, {&a.A9, &b.A3}, {&a.A10, &b.A2}, {&a.A11, &b.A1}, {&a.A7, &b.A11}, {&a.A8, &b.A10}, {&a.A9, &b.A9}, {&a.A10, &b.A8}, {&a.A11, &b.A7}}, []int{1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242, 242, 242})

	// d7  =  c7  + 18 * c13 + 242 * c19
	d7 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A7}, {&a.A1, &b.A6}, {&a.A2, &b.A5}, {&a.A3, &b.A4}, {&a.A4, &b.A3}, {&a.A5, &b.A2}, {&a.A6, &b.A1}, {&a.A7, &b.A0}, {&a.A2, &b.A11}, {&a.A3, &b.A10}, {&a.A4, &b.A9}, {&a.A5, &b.A8}, {&a.A6, &b.A7}, {&a.A7, &b.A6}, {&a.A8, &b.A5}, {&a.A9, &b.A4}, {&a.A10, &b.A3}, {&a.A11, &b.A2}, {&a.A8, &b.A11}, {&a.A9, &b.A10}, {&a.A10, &b.A9}, {&a.A11, &b.A8}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242, 242})

	// d8  =  c8  + 18 * c14 + 242 * c20
	d8 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A8}, {&a.A1, &b.A7}, {&a.A2, &b.A6}, {&a.A3, &b.A5}, {&a.A4, &b.A4}, {&a.A5, &b.A3}, {&a.A6, &b.A2}, {&a.A7, &b.A1}, {&a.A8, &b.A0}, {&a.A3, &b.A11}, {&a.A4, &b.A10}, {&a.A5, &b.A9}, {&a.A6, &b.A8}, {&a.A7, &b.A7}, {&a.A8, &b.A6}, {&a.A9, &b.A5}, {&a.A10, &b.A4}, {&a.A11, &b.A3}, {&a.A9, &b.A11}, {&a.A10, &b.A10}, {&a.A11, &b.A9}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242})

	// d9  =  c9  + 18 * c15 + 242 * c21
	d9 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A9}, {&a.A1, &b.A8}, {&a.A2, &b.A7}, {&a.A3, &b.A6}, {&a.A4, &b.A5}, {&a.A5, &b.A4}, {&a.A6, &b.A3}, {&a.A7, &b.A2}, {&a.A8, &b.A1}, {&a.A9, &b.A0}, {&a.A4, &b.A11}, {&a.A5, &b.A10}, {&a.A6, &b.A9}, {&a.A7, &b.A8}, {&a.A8, &b.A7}, {&a.A9, &b.A6}, {&a.A10, &b.A5}, {&a.A11, &b.A4}, {&a.A10, &b.A11}, {&a.A11, &b.A10}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242})

	// d10 =  c10 + 18 * c16 + 242 * c22
	d10 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A10}, {&a.A1, &b.A9}, {&a.A2, &b.A8}, {&a.A3, &b.A7}, {&a.A4, &b.A6}, {&a.A5, &b.A5}, {&a.A6, &b.A4}, {&a.A7, &b.A3}, {&a.A8, &b.A2}, {&a.A9, &b.A1}, {&a.A10, &b.A0}, {&a.A5, &b.A11}, {&a.A6, &b.A10}, {&a.A7, &b.A9}, {&a.A8, &b.A8}, {&a.A9, &b.A7}, {&a.A10, &b.A6}, {&a.A11, &b.A5}, {&a.A11, &b.A11}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 242})

	// d11 =  c11 + 18 * c17
	d11 := e.fp.Eval([][]*baseEl{{&a.A0, &b.A11}, {&a.A1, &b.A10}, {&a.A2, &b.A9}, {&a.A3, &b.A8}, {&a.A4, &b.A7}, {&a.A5, &b.A6}, {&a.A6, &b.A5}, {&a.A7, &b.A4}, {&a.A8, &b.A3}, {&a.A9, &b.A2}, {&a.A10, &b.A1}, {&a.A11, &b.A0}, {&a.A6, &b.A11}, {&a.A7, &b.A10}, {&a.A8, &b.A9}, {&a.A9, &b.A8}, {&a.A10, &b.A7}, {&a.A11, &b.A6}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18})

	return &E12{
		A0:  *d0,
		A1:  *d1,
		A2:  *d2,
		A3:  *d3,
		A4:  *d4,
		A5:  *d5,
		A6:  *d6,
		A7:  *d7,
		A8:  *d8,
		A9:  *d9,
		A10: *d10,
		A11: *d11,
	}
}

// SquareDirect squares coefficient-wise, without the ring. Kept for comparison
// against [Ext12.Square].
func (e Ext12) SquareDirect(a *E12) *E12 {

	//  d0  =  a0 a0  - 82 * (2 a1 a11 + 2 a2 a10 + 2 a3 a9 + 2 a4 a8 + 2 a5 a7 + a6 a6) - 1476 * (2 a7 a11 + 2 a8 a10 + a9 a9)
	d0 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A0}, {&a.A1, &a.A11}, {&a.A2, &a.A10}, {&a.A3, &a.A9}, {&a.A4, &a.A8}, {&a.A5, &a.A7}, {&a.A6, &a.A6}, {&a.A7, &a.A11}, {&a.A8, &a.A10}, {&a.A9, &a.A9}}, []int{1, -164, -164, -164, -164, -164, -82, -2952, -2952, -1476})

	// d1  =  2 a0 a1  - 164 * (2 a2 a11 + a3 a10 + a4 a9 + a5 a8 + a6 a7) - 2952 * (a8 a11 + a9 a10)
	d1 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A1}, {&a.A2, &a.A11}, {&a.A3, &a.A10}, {&a.A4, &a.A9}, {&a.A5, &a.A8}, {&a.A6, &a.A7}, {&a.A8, &a.A11}, {&a.A9, &a.A10}}, []int{2, -164, -164, -164, -164, -164, -2952, -2952})

	// d2  =  2 a0 a2 + a1 a1  - 82 * (2 a3 a11 + 2 a4 a10 + 2 a5 a9 + 2 a6 a8 + a7 a7) - 1476 * (2 a9 a11 + a10 a10)
	d2 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A2}, {&a.A1, &a.A1}, {&a.A3, &a.A11}, {&a.A4, &a.A10}, {&a.A5, &a.A9}, {&a.A6, &a.A8}, {&a.A7, &a.A7}, {&a.A9, &a.A11}, {&a.A10, &a.A10}}, []int{2, 1, -164, -164, -164, -164, -82, -2952, -1476})

	// d3  =  2 a0 a3 + 2 a1 a2  - 164 * (a4 a11 + a5 a10 + a6 a9 + a7 a8) - 2952 * a10 a11
	d3 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A3}, {&a.A1, &a.A2}, {&a.A4, &a.A11}, {&a.A5, &a.A10}, {&a.A6, &a.A9}, {&a.A7, &a.A8}, {&a.A10, &a.A11}}, []int{2, 2, -164, -164, -164, -164, -2952})

	// d4  =  2 a0 a4 + 2 a1 a3 + a2 a2  - 82 * (2 a5 a11 + 2 a6 a10 + 2 a7 a9 + a8 a8) - 1476 * a11 a11
	d4 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A4}, {&a.A1, &a.A3}, {&a.A2, &a.A2}, {&a.A5, &a.A11}, {&a.A6, &a.A10}, {&a.A7, &a.A9}, {&a.A8, &a.A8}, {&a.A11, &a.A11}}, []int{2, 2, 1, -164, -164, -164, -82, -1476})

	// d5  =  2 (a0 a5 + a1 a4 + a2 a3) - 164 * (a6 a11 + a7 a10 + a8 a9)
	d5 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A5}, {&a.A1, &a.A4}, {&a.A2, &a.A3}, {&a.A6, &a.A11}, {&a.A7, &a.A10}, {&a.A8, &a.A9}}, []int{2, 2, 2, -164, -164, -164})

	// d6  =  2 a0 a6 + 2 a1 a5 + 2 a2 a4 + a3 a3  + 18 * (2 a1 a11 + 2 a2 a10 + 2 a3 a9 + 2 a4 a8 + 2 a5 a7 + a6 a6) + 242 * (2 a7 a11 + 2 a8 a10 + a9 a9)
	d6 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A6}, {&a.A1, &a.A5}, {&a.A2, &a.A4}, {&a.A3, &a.A3}, {&a.A1, &a.A11}, {&a.A2, &a.A10}, {&a.A3, &a.A9}, {&a.A4, &a.A8}, {&a.A5, &a.A7}, {&a.A6, &a.A6}, {&a.A7, &a.A11}, {&a.A8, &a.A10}, {&a.A9, &a.A9}}, []int{2, 2, 2, 1, 36, 36, 36, 36, 36, 18, 484, 484, 242})

	// d7  =  2(a0 a7 + a1 a6 + a2 a5 + a3 a4)  + 36 * (a2 a11 + a3 a10 + a4 a9 + a5 a8 + a6 a7) + 484 * (a8 a11 + a9 a10)
	d7 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A7}, {&a.A1, &a.A6}, {&a.A2, &a.A5}, {&a.A3, &a.A4}, {&a.A2, &a.A11}, {&a.A3, &a.A10}, {&a.A4, &a.A9}, {&a.A5, &a.A8}, {&a.A6, &a.A7}, {&a.A8, &a.A11}, {&a.A9, &a.A10}}, []int{2, 2, 2, 2, 36, 36, 36, 36, 36, 484, 484})

	// d8  =  2(a0 a8 + a1 a7 + a2 a6 + a3 a5) + a4 a4  + 18 * (2 a3 a11 + 2 a4 a10 + 2 a5 a9 + 2 a6 a8 + a7 a7) + 242 * (2 a9 a11 + a10 a10)
	d8 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A8}, {&a.A1, &a.A7}, {&a.A2, &a.A6}, {&a.A3, &a.A5}, {&a.A4, &a.A4}, {&a.A3, &a.A11}, {&a.A4, &a.A10}, {&a.A5, &a.A9}, {&a.A6, &a.A8}, {&a.A7, &a.A7}, {&a.A9, &a.A11}, {&a.A10, &a.A10}}, []int{2, 2, 2, 2, 1, 36, 36, 36, 36, 18, 484, 242})

	// d9  =  2(a0 a9 + a1 a8 + a2 a7 + a3 a6 + a4 a5)  + 36 * (a4 a11 + a5 a10 + a6 a9 + a7 a8) + 484 * a10 a11
	d9 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A9}, {&a.A1, &a.A8}, {&a.A2, &a.A7}, {&a.A3, &a.A6}, {&a.A4, &a.A5}, {&a.A4, &a.A11}, {&a.A5, &a.A10}, {&a.A6, &a.A9}, {&a.A7, &a.A8}, {&a.A10, &a.A11}}, []int{2, 2, 2, 2, 2, 36, 36, 36, 36, 484})

	// d10 =  2(a0 a10 + a1 a9 + a2 a8 + a3 a7 + a4 a6) + a5 a5 + 18 * (2 a5 a11 + 2 a6 a10 + 2 a7 a9 + a8 a8) + 242 * a11 a11
	d10 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A10}, {&a.A1, &a.A9}, {&a.A2, &a.A8}, {&a.A3, &a.A7}, {&a.A4, &a.A6}, {&a.A5, &a.A5}, {&a.A5, &a.A11}, {&a.A6, &a.A10}, {&a.A7, &a.A9}, {&a.A8, &a.A8}, {&a.A11, &a.A11}}, []int{2, 2, 2, 2, 2, 1, 36, 36, 36, 18, 242})

	// d11 =  2(a0 a11 + a1 a10 + a2 a9 + a3 a8 + a4 a7 + a5 a6) + 36 * (a6 a11 + a7 a10 + a8 a9)
	d11 := e.fp.Eval([][]*baseEl{{&a.A0, &a.A11}, {&a.A1, &a.A10}, {&a.A2, &a.A9}, {&a.A3, &a.A8}, {&a.A4, &a.A7}, {&a.A5, &a.A6}, {&a.A6, &a.A11}, {&a.A7, &a.A10}, {&a.A8, &a.A9}}, []int{2, 2, 2, 2, 2, 2, 36, 36, 36})

	return &E12{
		A0:  *d0,
		A1:  *d1,
		A2:  *d2,
		A3:  *d3,
		A4:  *d4,
		A5:  *d5,
		A6:  *d6,
		A7:  *d7,
		A8:  *d8,
		A9:  *d9,
		A10: *d10,
		A11: *d11,
	}
}

// CyclotomicSquareGS is Granger-Scott's cyclotomic square,
// https://eprint.iacr.org/2009/565.pdf, 3.2. Only correct for elements of the
// cyclotomic subgroup.
func (e Ext12) CyclotomicSquareGS(x *E12) *E12 {
	tower := e.ToTower(x)

	z000 := e.fp.Eval([][]*baseEl{{tower[8], tower[8]}, {tower[9], tower[9]}, {tower[8], tower[9]}, {tower[0], tower[0]}, {tower[1], tower[1]}, {tower[0]}}, []int{27, -27, -6, 3, -3, -2})
	z001 := e.fp.Eval([][]*baseEl{{tower[8], tower[8]}, {tower[9], tower[9]}, {tower[8], tower[9]}, {tower[0], tower[1]}, {tower[1]}}, []int{3, -3, 54, 6, -2})
	z010 := e.fp.Eval([][]*baseEl{{tower[4], tower[4]}, {tower[5], tower[5]}, {tower[4], tower[5]}, {tower[6], tower[6]}, {tower[7], tower[7]}, {tower[2]}}, []int{27, -27, -6, 3, -3, -2})
	z011 := e.fp.Eval([][]*baseEl{{tower[4], tower[4]}, {tower[5], tower[5]}, {tower[4], tower[5]}, {tower[6], tower[7]}, {tower[3]}}, []int{3, -3, 54, 6, -2})
	z020 := e.fp.Eval([][]*baseEl{{tower[10], tower[10]}, {tower[11], tower[11]}, {tower[10], tower[11]}, {tower[2], tower[2]}, {tower[3], tower[3]}, {tower[4]}}, []int{27, -27, -6, 3, -3, -2})
	z021 := e.fp.Eval([][]*baseEl{{tower[10], tower[10]}, {tower[11], tower[11]}, {tower[10], tower[11]}, {tower[2], tower[3]}, {tower[5]}}, []int{3, -3, 54, 6, -2})
	z100 := e.fp.Eval([][]*baseEl{{tower[2], tower[10]}, {tower[3], tower[11]}, {tower[2], tower[11]}, {tower[3], tower[10]}, {tower[6]}}, []int{54, -54, -6, -6, 2})
	z101 := e.fp.Eval([][]*baseEl{{tower[2], tower[10]}, {tower[3], tower[11]}, {tower[2], tower[11]}, {tower[3], tower[10]}, {tower[7]}}, []int{6, -6, 54, 54, 2})
	z110 := e.fp.Eval([][]*baseEl{{tower[0], tower[8]}, {tower[1], tower[9]}, {tower[8]}}, []int{6, -6, 2})
	z111 := e.fp.Eval([][]*baseEl{{tower[0], tower[9]}, {tower[1], tower[8]}, {tower[9]}}, []int{6, 6, 2})
	z120 := e.fp.Eval([][]*baseEl{{tower[4], tower[6]}, {tower[5], tower[7]}, {tower[10]}}, []int{6, -6, 2})
	z121 := e.fp.Eval([][]*baseEl{{tower[4], tower[7]}, {tower[5], tower[6]}, {tower[11]}}, []int{6, 6, 2})

	return e.FromTower([12]*baseEl{z000, z001, z010, z011, z020, z021, z100, z101, z110, z111, z120, z121})
}

// Inverse returns x⁻¹, hinted and then checked with a single ring product.
func (e Ext12) Inverse(x *E12) *E12 {
	return e.PolyToE12(e.InversePoly(x.ToPoly()))
}

// InversePoly returns the inverse of the polynomial x. The hinted inverse is an
// operand of the ring check that constrains it, so it is committed to before
// the Schwartz-Zippel challenge is drawn.
func (e Ext12) InversePoly(xPoly *basePoly) *basePoly {
	x := xPoly.Coeffs
	res, err := e.fp.NewHint(inverseE12Hint, 12, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := &basePoly{
		Coeffs: []*baseEl{
			res[0], res[1], res[2], res[3], res[4], res[5],
			res[6], res[7], res[8], res[9], res[10], res[11]},
	}
	e.ToCommit(xPoly, inv)

	// 1 == inv * x
	e.AssertIsEqual(e.One(), e.PolyToE12(e.MulPoly(xPoly, inv)))

	return inv
}

// DivUnchecked returns x/y. It is unchecked in the sense that a zero y makes
// the constraints unsatisfiable rather than yielding a defined result.
func (e Ext12) DivUnchecked(x, y *E12) *E12 {
	res, err := e.fp.NewHint(divE12Hint, 12, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5, &x.A6, &x.A7, &x.A8, &x.A9, &x.A10, &x.A11, &y.A0, &y.A1, &y.A2, &y.A3, &y.A4, &y.A5, &y.A6, &y.A7, &y.A8, &y.A9, &y.A10, &y.A11)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E12{A0: *res[0], A1: *res[1], A2: *res[2], A3: *res[3], A4: *res[4], A5: *res[5], A6: *res[6], A7: *res[7], A8: *res[8], A9: *res[9], A10: *res[10], A11: *res[11]}

	// x == div * y
	e.AssertIsEqual(x, e.Mul(&div, y))

	return &div
}

func (e Ext12) AssertIsEqual(a, b *E12) {
	e.fp.AssertIsEqual(&a.A0, &b.A0)
	e.fp.AssertIsEqual(&a.A1, &b.A1)
	e.fp.AssertIsEqual(&a.A2, &b.A2)
	e.fp.AssertIsEqual(&a.A3, &b.A3)
	e.fp.AssertIsEqual(&a.A4, &b.A4)
	e.fp.AssertIsEqual(&a.A5, &b.A5)
	e.fp.AssertIsEqual(&a.A6, &b.A6)
	e.fp.AssertIsEqual(&a.A7, &b.A7)
	e.fp.AssertIsEqual(&a.A8, &b.A8)
	e.fp.AssertIsEqual(&a.A9, &b.A9)
	e.fp.AssertIsEqual(&a.A10, &b.A10)
	e.fp.AssertIsEqual(&a.A11, &b.A11)
}

func (e Ext12) IsEqual(x, y *E12) frontend.Variable {
	diff0 := e.fp.Sub(&x.A0, &y.A0)
	diff1 := e.fp.Sub(&x.A1, &y.A1)
	diff2 := e.fp.Sub(&x.A2, &y.A2)
	diff3 := e.fp.Sub(&x.A3, &y.A3)
	diff4 := e.fp.Sub(&x.A4, &y.A4)
	diff5 := e.fp.Sub(&x.A5, &y.A5)
	diff6 := e.fp.Sub(&x.A6, &y.A6)
	diff7 := e.fp.Sub(&x.A7, &y.A7)
	diff8 := e.fp.Sub(&x.A8, &y.A8)
	diff9 := e.fp.Sub(&x.A9, &y.A9)
	diff10 := e.fp.Sub(&x.A10, &y.A10)
	diff11 := e.fp.Sub(&x.A11, &y.A11)
	isZero0 := e.fp.IsZero(diff0)
	isZero1 := e.fp.IsZero(diff1)
	isZero2 := e.fp.IsZero(diff2)
	isZero3 := e.fp.IsZero(diff3)
	isZero4 := e.fp.IsZero(diff4)
	isZero5 := e.fp.IsZero(diff5)
	isZero6 := e.fp.IsZero(diff6)
	isZero7 := e.fp.IsZero(diff7)
	isZero8 := e.fp.IsZero(diff8)
	isZero9 := e.fp.IsZero(diff9)
	isZero10 := e.fp.IsZero(diff10)
	isZero11 := e.fp.IsZero(diff11)

	return e.api.And(
		e.api.And(
			e.api.And(e.api.And(isZero0, isZero1), e.api.And(isZero2, isZero3)),
			e.api.And(e.api.And(isZero4, isZero5), e.api.And(isZero6, isZero7)),
		),
		e.api.And(e.api.And(isZero8, isZero9), e.api.And(isZero10, isZero11)),
	)
}

func (e Ext12) Copy(x *E12) *E12 {
	return &E12{
		A0:  x.A0,
		A1:  x.A1,
		A2:  x.A2,
		A3:  x.A3,
		A4:  x.A4,
		A5:  x.A5,
		A6:  x.A6,
		A7:  x.A7,
		A8:  x.A8,
		A9:  x.A9,
		A10: x.A10,
		A11: x.A11,
	}
}

func (e Ext12) Frobenius(a *E12) *E12 {
	tower := e.ToTower(a)

	tower[1] = e.fp.Neg(tower[1])
	tower[3] = e.fp.Neg(tower[3])
	tower[5] = e.fp.Neg(tower[5])
	tower[7] = e.fp.Neg(tower[7])
	tower[9] = e.fp.Neg(tower[9])
	tower[11] = e.fp.Neg(tower[11])

	t1 := e.Ext2.MulByNonResidue1Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue1Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue1Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue1Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue1Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

func (e Ext12) FrobeniusSquare(a *E12) *E12 {
	tower := e.ToTower(a)

	t1 := e.Ext2.MulByNonResidue2Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue2Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue2Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue2Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue2Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

func (e Ext12) FrobeniusCube(a *E12) *E12 {
	tower := e.ToTower(a)

	tower[1] = e.fp.Neg(tower[1])
	tower[3] = e.fp.Neg(tower[3])
	tower[5] = e.fp.Neg(tower[5])
	tower[7] = e.fp.Neg(tower[7])
	tower[9] = e.fp.Neg(tower[9])
	tower[11] = e.fp.Neg(tower[11])

	t1 := e.Ext2.MulByNonResidue3Power2(&E2{A0: *tower[2], A1: *tower[3]})
	t2 := e.Ext2.MulByNonResidue3Power4(&E2{A0: *tower[4], A1: *tower[5]})
	t3 := e.Ext2.MulByNonResidue3Power1(&E2{A0: *tower[6], A1: *tower[7]})
	t4 := e.Ext2.MulByNonResidue3Power3(&E2{A0: *tower[8], A1: *tower[9]})
	t5 := e.Ext2.MulByNonResidue3Power5(&E2{A0: *tower[10], A1: *tower[11]})

	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(&t3.A0, e.fp.MulConst(&t3.A1, nine))
	A2 := e.fp.Sub(&t1.A0, e.fp.MulConst(&t1.A1, nine))
	A3 := e.fp.Sub(&t4.A0, e.fp.MulConst(&t4.A1, nine))
	A4 := e.fp.Sub(&t2.A0, e.fp.MulConst(&t2.A1, nine))
	A5 := e.fp.Sub(&t5.A0, e.fp.MulConst(&t5.A1, nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  t3.A1,
		A8:  t1.A1,
		A9:  t4.A1,
		A10: t2.A1,
		A11: t5.A1,
	}
}

// FromE12 converts a gnark-crypto 𝔽p¹² element -- a quadratic over cubic over
// quadratic tower -- into the direct extension witness form used here. The two
// towers are isomorphic and the coefficients are permuted as follows:
//
//	tower  = a000 a001 a010 a011 a020 a021 a100 a101 a110 a111 a120 a121
//	direct = a0   a1   a2   a3   a4   a5   a6   a7   a8   a9   a10  a11
//
//	A0  =  a000 - 9 * a001    A6  =  a001
//	A1  =  a100 - 9 * a101    A7  =  a101
//	A2  =  a010 - 9 * a011    A8  =  a011
//	A3  =  a110 - 9 * a111    A9  =  a111
//	A4  =  a020 - 9 * a021    A10 =  a021
//	A5  =  a120 - 9 * a121    A11 =  a121
func FromE12(a *bn254.E12) E12 {
	var c0, c1, c2, c3, c4, c5, t fp_bn.Element
	t.SetUint64(9).Mul(&t, &a.C0.B0.A1)
	c0.Sub(&a.C0.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B0.A1)
	c1.Sub(&a.C1.B0.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B1.A1)
	c2.Sub(&a.C0.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B1.A1)
	c3.Sub(&a.C1.B1.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C0.B2.A1)
	c4.Sub(&a.C0.B2.A0, &t)
	t.SetUint64(9).Mul(&t, &a.C1.B2.A1)
	c5.Sub(&a.C1.B2.A0, &t)

	return E12{
		A0:  emulated.ValueOf[emulated.BN254Fp](c0),
		A1:  emulated.ValueOf[emulated.BN254Fp](c1),
		A2:  emulated.ValueOf[emulated.BN254Fp](c2),
		A3:  emulated.ValueOf[emulated.BN254Fp](c3),
		A4:  emulated.ValueOf[emulated.BN254Fp](c4),
		A5:  emulated.ValueOf[emulated.BN254Fp](c5),
		A6:  emulated.ValueOf[emulated.BN254Fp](a.C0.B0.A1),
		A7:  emulated.ValueOf[emulated.BN254Fp](a.C1.B0.A1),
		A8:  emulated.ValueOf[emulated.BN254Fp](a.C0.B1.A1),
		A9:  emulated.ValueOf[emulated.BN254Fp](a.C1.B1.A1),
		A10: emulated.ValueOf[emulated.BN254Fp](a.C0.B2.A1),
		A11: emulated.ValueOf[emulated.BN254Fp](a.C1.B2.A1),
	}
}

// ToTower converts the direct representation into the gnark-crypto tower
// coefficients, the inverse of the permutation documented on [FromE12]:
//
//	a000 = A0 + 9*A6    a010 = A2 + 9*A8    a020 = A4 + 9*A10
//	a001 = A6           a011 = A8           a021 = A10
//	a100 = A1 + 9*A7    a110 = A3 + 9*A9    a120 = A5 + 9*A11
//	a101 = A7           a111 = A9           a121 = A11
func (e Ext12) ToTower(a *E12) [12]*baseEl {
	nine := big.NewInt(9)
	a000 := e.fp.Add(&a.A0, e.fp.MulConst(&a.A6, nine))
	a001 := &a.A6
	a010 := e.fp.Add(&a.A2, e.fp.MulConst(&a.A8, nine))
	a011 := &a.A8
	a020 := e.fp.Add(&a.A4, e.fp.MulConst(&a.A10, nine))
	a021 := &a.A10
	a100 := e.fp.Add(&a.A1, e.fp.MulConst(&a.A7, nine))
	a101 := &a.A7
	a110 := e.fp.Add(&a.A3, e.fp.MulConst(&a.A9, nine))
	a111 := &a.A9
	a120 := e.fp.Add(&a.A5, e.fp.MulConst(&a.A11, nine))
	a121 := &a.A11

	return [12]*baseEl{a000, a001, a010, a011, a020, a021, a100, a101, a110, a111, a120, a121}
}

// FromTower is the inverse of [Ext12.ToTower].
func (e Ext12) FromTower(tower [12]*baseEl) *E12 {
	nine := big.NewInt(9)
	A0 := e.fp.Sub(tower[0], e.fp.MulConst(tower[1], nine))
	A1 := e.fp.Sub(tower[6], e.fp.MulConst(tower[7], nine))
	A2 := e.fp.Sub(tower[2], e.fp.MulConst(tower[3], nine))
	A3 := e.fp.Sub(tower[8], e.fp.MulConst(tower[9], nine))
	A4 := e.fp.Sub(tower[4], e.fp.MulConst(tower[5], nine))
	A5 := e.fp.Sub(tower[10], e.fp.MulConst(tower[11], nine))

	return &E12{
		A0:  *A0,
		A1:  *A1,
		A2:  *A2,
		A3:  *A3,
		A4:  *A4,
		A5:  *A5,
		A6:  *tower[1],
		A7:  *tower[7],
		A8:  *tower[3],
		A9:  *tower[9],
		A10: *tower[5],
		A11: *tower[11],
	}
}
