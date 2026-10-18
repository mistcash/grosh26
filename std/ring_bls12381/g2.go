package ring_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/ringpairing"
)

// g2Point is an affine point on the BLS12-381 twist. gnark's own G2 point type
// is unexported, so the ladder uses this one and converts at the G2Affine
// boundary.
type g2Point struct {
	X, Y fields_bls12381.E2
}

// line is a line evaluation as the ladder returns it: R0 = λ, R1 = λ·x - y.
type line struct {
	R0, R1 fields_bls12381.E2
}

// ψ constants, same values as gnark's G2 (sw_bls12381/g2.go NewG2):
// x ↦ psiX·(x.A1 + x.A0·u), y ↦ psiY·ȳ.
const (
	psiX   = "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437"
	psiYA0 = "2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"
	psiYA1 = "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"
)

// ComputeLines runs the [|x₀|]Q ladder, opening with a tripling for the two
// leading ones of the seed. Q is asserted to be on the twist first, with
// gnark's check; the prime-order subgroup check ψ(Q) == [x₀]Q then reuses the
// ladder endpoint, exactly like gnark's own computeLines.
func (c *curve) ComputeLines(Q *G2Affine) *ringpairing.Lines[emulated.BLS12381Fp] {
	c.g.AssertIsOnTwist(Q)

	q := &g2Point{X: Q.P.X, Y: Q.P.Y}
	loopCounter := bls12381.LoopCounter
	n := len(loopCounter)
	lines := ringpairing.NewLines[emulated.BLS12381Fp](n - 1)
	set := func(half, i int, l *line) { lines[half][i] = toLine(&l.R0, &l.R1) }

	acc, l0, l1 := c.tripleStep(q)
	set(0, n-2, l0)
	set(1, n-2, l1)
	for i := n - 3; i >= 0; i-- {
		if loopCounter[i] == 0 {
			acc, l0 = c.doubleStep(acc)
			set(0, i, l0)
		} else {
			acc, l0, l1 = c.doubleAndAddStep(acc, q)
			set(0, i, l0)
			set(1, i, l1)
		}
	}

	// acc == [|x₀|]Q and x₀ < 0, so ψ(Q) == [x₀]Q is ψ(Q) == -acc
	psiQ := c.psi(q)
	c.ext2.AssertIsEqual(&acc.X, &psiQ.X)
	c.ext2.AssertIsEqual(c.ext2.Neg(&acc.Y), &psiQ.Y)
	return lines
}

// psi maps q through ψ: x ↦ psiX·(x.A1 + x.A0·u), y ↦ psiY·ȳ.
func (c *curve) psi(q *g2Point) *g2Point {
	x := c.ext2.MulByElement(&q.X, c.fp.NewElement(psiX))
	psiY := &fields_bls12381.E2{A0: *c.fp.NewElement(psiYA0), A1: *c.fp.NewElement(psiYA1)}
	return &g2Point{
		X: fields_bls12381.E2{A0: x.A1, A1: x.A0},
		Y: *c.ext2.Mul(c.ext2.Conjugate(&q.Y), psiY),
	}
}

// doubleStep doubles p1 and evaluates the tangent line at p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (c *curve) doubleStep(p1 *g2Point) (*g2Point, *line) {
	// λ = 3x²/2y
	λ := c.divE2WithZeroGuard(
		c.ext2.MulByConstElement(c.ext2.Square(&p1.X), big.NewInt(3)),
		c.ext2.MulByConstElement(&p1.Y, big.NewInt(2)),
	)
	// xr = λ²-2x
	xr := &fields_bls12381.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}}, []int{1, -1, -2}),
		A1: *c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}}, []int{2, -2}),
	}
	return c.pointOn(λ, xr, p1), c.lineThrough(λ, p1)
}

// doubleAndAddStep computes 2p1 + p2 as (p1 + p2) + p1, and evaluates the
// lines through p1 and p2 and through p1 and p1 + p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (c *curve) doubleAndAddStep(p1, p2 *g2Point) (*g2Point, *line, *line) {
	// λ1 = (y1-y2)/(x1-x2)
	λ1 := c.divE2WithZeroGuard(c.ext2.Sub(&p1.Y, &p2.Y), c.ext2.Sub(&p1.X, &p2.X))
	// x3 = λ1²-x1-x2; y3 is not needed
	x3 := c.chord(λ1, &p1.X, &p2.X)
	// λ2 = -λ1-2y1/(x3-x1)
	λ2 := c.divE2WithZeroGuard(c.ext2.MulByConstElement(&p1.Y, big.NewInt(2)), c.ext2.Sub(x3, &p1.X))
	λ2 = c.ext2.Neg(c.ext2.Add(λ2, λ1))
	// x4 = λ2²-x1-x3
	p4 := c.pointOn(λ2, c.chord(λ2, &p1.X, x3), p1)
	return p4, c.lineThrough(λ1, p1), c.lineThrough(λ2, p1)
}

// tripleStep computes 3p1 as 2p1 + p1, and evaluates the tangent at p1 and the
// line through p1 and 2p1.
func (c *curve) tripleStep(p1 *g2Point) (*g2Point, *line, *line) {
	// λ1 = 3x²/2y
	d := c.ext2.Double(&p1.Y)
	λ1 := c.divE2WithZeroGuard(c.ext2.MulByConstElement(c.ext2.Square(&p1.X), big.NewInt(3)), d)
	// x2 = λ1²-2x
	x2 := &fields_bls12381.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}}, []int{1, -1, -2}),
		A1: *c.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}}, []int{2, -2}),
	}
	// λ2 = 2y/(x2 − x) − λ1, so y2 is not needed
	λ2 := c.ext2.Sub(c.divE2WithZeroGuard(d, c.ext2.Sub(&p1.X, x2)), λ1)
	p3 := c.pointOn(λ2, c.chord(λ2, &p1.X, x2), p1)
	return p3, c.lineThrough(λ1, p1), c.lineThrough(λ2, p1)
}

// chord returns λ² - x1 - x2, the x-coordinate of the third point on the line
// of slope λ through points with x-coordinates x1 and x2.
func (c *curve) chord(λ, x1, x2 *fields_bls12381.E2) *fields_bls12381.E2 {
	return &fields_bls12381.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&x1.A0}, {&x2.A0}}, []int{1, -1, -1, -1}),
		A1: *c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&x1.A1}, {&x2.A1}}, []int{2, -1, -1}),
	}
}

// pointOn returns (xr, λ(x1-xr) - y1): the point at xr on the line of slope λ
// through p1, negated.
func (c *curve) pointOn(λ, xr *fields_bls12381.E2, p1 *g2Point) *g2Point {
	d := c.ext2.Sub(&p1.X, xr)
	return &g2Point{X: *xr, Y: fields_bls12381.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1}),
		A1: *c.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1}),
	}}
}

// lineThrough returns the line of slope λ through p: R0 = λ, R1 = λ·x - y.
func (c *curve) lineThrough(λ *fields_bls12381.E2, p *g2Point) *line {
	return &line{R0: *λ, R1: fields_bls12381.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A0}, {&λ.A1, &p.X.A1}, {&p.Y.A0}}, []int{1, -1, -1}),
		A1: *c.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A1}, {&λ.A1, &p.X.A0}, {&p.Y.A1}}, []int{1, 1, -1}),
	}}
}

// divE2WithZeroGuard computes n/d as a line slope, but for d == 0 it returns 0
// with the quotient constrained to 0 rather than left as a free hint value. A
// plain DivUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0, which leaves λ
// unconstrained -- the soundness gap when the point at infinity (0,0) reaches
// the Miller loop and every affine line evaluation becomes 0/0.
func (c *curve) divE2WithZeroGuard(n, d *fields_bls12381.E2) *fields_bls12381.E2 {
	dIsZero := c.ext2.IsZero(d)
	dSafe := c.ext2.Select(dIsZero, c.ext2.One(), d)
	return c.ext2.Select(dIsZero, c.ext2.Zero(), c.ext2.DivUnchecked(n, dSafe))
}
