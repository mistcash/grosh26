package polyring

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

var one = big.NewInt(1)

// Poly is an element of a polynomial ring over the emulated field: a slice of
// coefficients in ascending degree order, so Coeffs[i] multiplies xⁱ. A nil
// coefficient is zero, which keeps sparse polynomials cheap.
type Poly[T emulated.FieldParams] struct {
	Coeffs     []*emulated.Element[T]
	evaluation *emulated.Element[T] // nil unless evaluated
}

// EvalFnType evaluates a polynomial at a challenge point, given that point's
// powers: at[i] holds xⁱ. Pass one to [PolyRingChecker.NewPolyRingCheck] to
// override how a ring's modulus is evaluated.
type EvalFnType[T emulated.FieldParams] = func([]*emulated.Element[T]) *emulated.Element[T]

// PolyConv is implemented by types that can be viewed as a polynomial over the
// emulated field, so that structures built on top of the ring (extension field
// elements, say) can be fed to it directly.
type PolyConv[T emulated.FieldParams] interface {
	ToPoly() *Poly[T]
}

// ToPoly satisfies [PolyConv].
func (p *Poly[T]) ToPoly() *Poly[T] {
	return p
}

// MakePoly builds a polynomial from coefficients in ascending degree order.
// Each coefficient is anything [emulated.Field.NewElement] accepts, and a
// literal 0 becomes the zero element.
func (prc *PolyRingChecker[T]) MakePoly(coeffs ...any) *Poly[T] {
	poly := &Poly[T]{}
	poly.Coeffs = make([]*emulated.Element[T], len(coeffs))

	for i, coeff := range coeffs {
		if coeff == 0 {
			poly.Coeffs[i] = prc.f.Zero()
			continue
		}
		poly.Coeffs[i] = prc.f.NewElement(coeff)
	}

	return poly
}

// evalPolyWithChallenge evaluates p at a point whose powers are given by at,
// where at[i] = at^i. Precomputing and sharing powers across multiple
// polynomial evaluations at the same point avoids redundant multiplications.
func (prc *PolyRingChecker[T]) evalPolyWithChallenge(p *Poly[T], at []*emulated.Element[T]) *emulated.Element[T] {
	if p.evaluation == nil {
		p.evaluation = prc.InnerProductNoReduce(p.Coeffs, at)
	}
	return p.evaluation
}

// InnerProduct computes the inner product of two vectors of emulated elements.
func (prc *PolyRingChecker[T]) InnerProduct(a, b []*emulated.Element[T]) *emulated.Element[T] {
	return prc.f.Reduce(prc.InnerProductNoReduce(a, b))
}

// InnerProductNoReduce computes the inner product of two vectors of
// emulated elements without performing reduction.
func (prc *PolyRingChecker[T]) InnerProductNoReduce(a, b []*emulated.Element[T]) *emulated.Element[T] {
	n := len(a)
	// only non-nil terms are collected: a nil or zero coefficient contributes
	// nothing, and [emulated.Field.Sum] would dereference it. Sparse polynomials --
	// line evaluations, the ring modulus -- leave most coefficients nil.
	terms := make([]*emulated.Element[T], 0, n)
	for i := 0; i < n; i++ {
		switch {
		case a[i] == nil || b[i] == nil || prc.isStrictZero(a[i]) || prc.isStrictZero(b[i]):
			// don't add anything, one of the multipliers is zero
		case isOne(prc.f, b[i]):
			terms = append(terms, a[i])
		case isOne(prc.f, a[i]):
			terms = append(terms, b[i])
		default:
			terms = append(terms, prc.f.MulNoReduce(a[i], b[i]))
		}
	}
	if len(terms) == 0 {
		return prc.f.Zero()
	}
	return prc.f.Sum(terms...)
}

// isStrictZero reports whether the element is zero by construction. Empty
// limbs denote the zero element. It is used for fast paths in the inner
// product.
func (prc *PolyRingChecker[T]) isStrictZero(e *emulated.Element[T]) bool {
	return len(e.Limbs) == 0 // if no limbs it's strictly 0
}

// isOne reports whether e is the constant one.
func isOne[T emulated.FieldParams](f *emulated.Field[T], e *emulated.Element[T]) bool {
	v, isConst := f.ConstantValue(e)
	return isConst && v.Cmp(one) == 0
}

// serialisePoly converts a polynomial into a slice of frontend.Variable
// suitable for hints. format is nbTerms|...terms
func (prc *PolyRingChecker[T]) serialisePoly(poly *Poly[T], inputs []frontend.Variable) []frontend.Variable {
	nbLimbs := int(prc.fp.NbLimbs())
	inputs = append(inputs, len(poly.Coeffs))
	for _, coeff := range poly.Coeffs {
		if coeff == nil || len(coeff.Limbs) == 0 {
			for i := 0; i < nbLimbs; i++ {
				inputs = append(inputs, 0)
			}
			continue
		}
		inputs = append(inputs, coeff.Limbs...)
		for i := len(coeff.Limbs); i < nbLimbs; i++ {
			inputs = append(inputs, 0)
		}
	}
	return inputs
}
