package polyring

import (
	"github.com/consensys/gnark/std/math/emulated"
)

// PolyRingAccumulator is used to accumulate polynomial products
// represents queue of ∏_i state_i operations
// optionally, performs multiplications via MulPolyRings when target
// degree is reached; alternatively can be used without a target
// degree, in which case it will only perform operations on Eval call
type PolyRingAccumulator[T emulated.FieldParams] struct {
	state      []*Poly[T] // current accumulated polynomials
	f          *emulated.Field[T]
	prc        *PolyRingChecker[T]
	checker    *PolyRingGroupChecks[T]
	targetDeg  int
	currentDeg int
}

// NewPolyRingAccumulator creates a new polynomial products accumulator
// targetDeg can be set to limit the degree of the accumulated
// polynomial targetDeg set to 0 means products will only happen
// when Eval is called
func (prc *PolyRingChecker[T]) NewPolyRingAccumulator(checker *PolyRingGroupChecks[T], targetDeg int) *PolyRingAccumulator[T] {
	return &PolyRingAccumulator[T]{
		f:         prc.f,
		prc:       prc,
		checker:   checker,
		targetDeg: targetDeg,
	}
}

// Mul adds a new polynomial to the accumulator, ∏_i state_i * poly
// if targetDeg is set and the accumulated degree would exceed it, Eval
// is called first to reduce the state before enqueuing
func (acc *PolyRingAccumulator[T]) Mul(poly *Poly[T]) *PolyRingAccumulator[T] {
	if acc.targetDeg != 0 && acc.currentDeg+len(poly.Coeffs)-1 > acc.targetDeg {
		acc.Eval()
	}
	acc.currentDeg += len(poly.Coeffs) - 1
	acc.state = append(acc.state, poly)
	return acc
}

// Sqr squares the current accumulation, i.e. ∏_i (state_i * state_i),
// doubling the degree; if targetDeg is set and the accumulated degree
// would exceed it, Eval is called to reduce the state before enqueuing
func (acc *PolyRingAccumulator[T]) Sqr() *PolyRingAccumulator[T] {
	if acc.targetDeg != 0 && acc.currentDeg+acc.currentDeg > acc.targetDeg {
		acc.Eval()
	}
	acc.currentDeg += acc.currentDeg // degree doubles
	acc.state = append(acc.state, acc.state...)
	return acc
}

// Eval multiplies all queued factors via MulPolyRings, collapses the state
// to the resulting polynomial, and returns it
// called automatically by Queue and Sqr when targetDeg is set and would be exceeded.
func (acc *PolyRingAccumulator[T]) Eval() (result *Poly[T]) {
	if len(acc.state) == 1 {
		return acc.state[0]
	}
	result, err := acc.prc.MulPolyRings(acc.checker, acc.state...)
	if err != nil {
		panic(err)
	}
	acc.state = []*Poly[T]{result}
	acc.currentDeg = len(result.Coeffs) - 1
	return
}
