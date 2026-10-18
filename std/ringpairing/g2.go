package ringpairing

import (
	"github.com/consensys/gnark/std/math/emulated"
)

// g2Point is an affine point on the twist. gnark's own G2 point types are
// unexported, so the ladder uses this one and converts at the G2Affine
// boundary.
type g2Point[F emulated.FieldParams] struct {
	X, Y e2[F]
}

// lineEval is one line of the Miller loop, as gnark stores it: R0 = λ, the
// slope, and R1 = λ·x - y for a point (x, y) on the line.
type lineEval[F emulated.FieldParams] struct {
	R0, R1 e2[F]
}

// lineEvals are a G2 point's lines, indexed [half][iteration] like gnark's:
// half 0 holds the doubling line, half 1 the addition line of a non-zero bit.
type lineEvals[F emulated.FieldParams] [2][]*lineEval[F]

func newLineEvals[F emulated.FieldParams](n int) *lineEvals[F] {
	return &lineEvals[F]{make([]*lineEval[F], n), make([]*lineEval[F], n)}
}

// ladder holds the affine twist steps both curves' Miller loops are built
// from. Each step returns the line(s) it evaluates alongside the new point.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
type ladder[F emulated.FieldParams] struct {
	ext2[F]
}

type el[F emulated.FieldParams] = emulated.Element[F]

// lineThrough returns the line of slope λ through p: R0 = λ, R1 = λ·x - y.
func (l ladder[F]) lineThrough(λ *e2[F], p *g2Point[F]) *lineEval[F] {
	return &lineEval[F]{R0: *λ, R1: e2[F]{
		A0: *l.fp.Eval([][]*el[F]{{&λ.A0, &p.X.A0}, {&λ.A1, &p.X.A1}, {&p.Y.A0}}, []int{1, -1, -1}),
		A1: *l.fp.Eval([][]*el[F]{{&λ.A0, &p.X.A1}, {&λ.A1, &p.X.A0}, {&p.Y.A1}}, []int{1, 1, -1}),
	}}
}

// chord returns x3 = λ² - x1 - x2, the x-coordinate of the third point on the
// line of slope λ through points with x-coordinates x1 and x2.
func (l ladder[F]) chord(λ, x1, x2 *e2[F]) *e2[F] {
	return &e2[F]{
		A0: *l.fp.Eval([][]*el[F]{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&x1.A0}, {&x2.A0}}, []int{1, -1, -1, -1}),
		A1: *l.fp.Eval([][]*el[F]{{&λ.A0, &λ.A1}, {&x1.A1}, {&x2.A1}}, []int{2, -1, -1}),
	}
}

// tangentX returns xr = λ² - 2x, chord with x1 == x2 == x.
func (l ladder[F]) tangentX(λ, x *e2[F]) *e2[F] {
	return &e2[F]{
		A0: *l.fp.Eval([][]*el[F]{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&x.A0}}, []int{1, -1, -2}),
		A1: *l.fp.Eval([][]*el[F]{{&λ.A0, &λ.A1}, {&x.A1}}, []int{2, -2}),
	}
}

// pointAt returns (xr, λ(x1-xr) - y1): the point at xr on the line of slope λ
// through p1, negated.
func (l ladder[F]) pointAt(λ, xr *e2[F], p1 *g2Point[F]) *g2Point[F] {
	d := l.sub(&p1.X, xr)
	return &g2Point[F]{X: *xr, Y: e2[F]{
		A0: *l.fp.Eval([][]*el[F]{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1}),
		A1: *l.fp.Eval([][]*el[F]{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1}),
	}}
}

// tangentSlope returns λ = 3x²/2y.
func (l ladder[F]) tangentSlope(p *g2Point[F]) *e2[F] {
	return l.divWithZeroGuard(l.mulByConst(l.square(&p.X), 3), l.mulByConst(&p.Y, 2))
}

// doubleStep doubles p1 and evaluates the tangent line at p1.
func (l ladder[F]) doubleStep(p1 *g2Point[F]) (*g2Point[F], *lineEval[F]) {
	λ := l.tangentSlope(p1)
	return l.pointAt(λ, l.tangentX(λ, &p1.X), p1), l.lineThrough(λ, p1)
}

// addStep adds p1 and p2 and evaluates the line through them.
func (l ladder[F]) addStep(p1, p2 *g2Point[F]) (*g2Point[F], *lineEval[F]) {
	λ := l.divWithZeroGuard(l.sub(&p2.Y, &p1.Y), l.sub(&p2.X, &p1.X))
	return l.pointAt(λ, l.chord(λ, &p1.X, &p2.X), p1), l.lineThrough(λ, p1)
}

// lineCompute evaluates the line through p1 and -p2 without computing the sum.
func (l ladder[F]) lineCompute(p1, p2 *g2Point[F]) *lineEval[F] {
	λ := l.divWithZeroGuard(l.add(&p1.Y, &p2.Y), l.sub(&p1.X, &p2.X))
	return l.lineThrough(λ, p1)
}

// doubleAndAddStep computes 2p1 ± p2 (- when isSub) as (p1 ± p2) + p1, and
// evaluates the lines through p1 and ±p2 and through p1 and p1 ± p2.
func (l ladder[F]) doubleAndAddStep(p1, p2 *g2Point[F], isSub bool) (*g2Point[F], *lineEval[F], *lineEval[F]) {
	// λ1 = (y1 ∓ y2)/(x1 - x2)
	var num *e2[F]
	if isSub {
		num = l.add(&p1.Y, &p2.Y)
	} else {
		num = l.sub(&p1.Y, &p2.Y)
	}
	λ1 := l.divWithZeroGuard(num, l.sub(&p1.X, &p2.X))
	// x3 = λ1² - x1 - x2; y3 is not needed
	x3 := l.chord(λ1, &p1.X, &p2.X)
	// λ2 = -λ1 - 2y1/(x3 - x1)
	λ2 := l.divWithZeroGuard(l.mulByConst(&p1.Y, 2), l.sub(x3, &p1.X))
	λ2 = l.neg(l.add(λ2, λ1))
	// x4 = λ2² - x1 - x3
	p4 := l.pointAt(λ2, l.chord(λ2, &p1.X, x3), p1)
	return p4, l.lineThrough(λ1, p1), l.lineThrough(λ2, p1)
}

// tripleStep computes 3p1 as 2p1 + p1, and evaluates the tangent at p1 and the
// line through p1 and 2p1.
func (l ladder[F]) tripleStep(p1 *g2Point[F]) (*g2Point[F], *lineEval[F], *lineEval[F]) {
	λ1 := l.tangentSlope(p1)
	x2 := l.tangentX(λ1, &p1.X)
	// λ2 = 2y/(x2 − x) − λ1, so y2 is not needed
	λ2 := l.sub(l.divWithZeroGuard(l.mulByConst(&p1.Y, 2), l.sub(&p1.X, x2)), λ1)
	p3 := l.pointAt(λ2, l.chord(λ2, &p1.X, x2), p1)
	return p3, l.lineThrough(λ1, p1), l.lineThrough(λ2, p1)
}

// addPoints adds p1 and p2 on the twist: incomplete affine addition, addStep
// without the line, and with an unguarded division like gnark's G2.add.
func (l ladder[F]) addPoints(p1, p2 *g2Point[F]) *g2Point[F] {
	λ := l.divUnchecked(l.sub(&p2.Y, &p1.Y), l.sub(&p2.X, &p1.X))
	return l.pointAt(λ, l.chord(λ, &p1.X, &p2.X), p1)
}
