package ring_bn254

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/ringpairing"
)

// g2Point is an affine point on the BN254 twist. gnark's own G2 point type is
// unexported, so the ladder uses this one and converts at the G2Affine
// boundary.
type g2Point struct {
	X, Y fields_bn254.E2
}

// ComputeLines runs the [6x₀+2]Q ladder. Q is asserted to be on the twist
// first, with gnark's check; the prime-order subgroup check then reuses the
// ladder endpoint instead of a separate scalar multiplication, exactly like
// gnark's own computeLines: [6x₀+2]Q + ψ(Q) + ψ³(Q) == ψ²(Q), see Sec. 3.1.2
// (Remark 2) of https://eprint.iacr.org/2022/348.
func (c *curve) ComputeLines(Q *G2Affine) *ringpairing.Lines[emulated.BN254Fp] {
	c.g.AssertIsOnTwist(Q)

	q := &g2Point{X: Q.P.X, Y: Q.P.Y}
	loopCounter := bn254.LoopCounter
	n := len(loopCounter)
	lines := ringpairing.NewLines[emulated.BN254Fp](n)

	setLine := func(half, i int, r0, r1 fields_bn254.E2) {
		lines[half][i] = toLine(&r0, &r1)
	}

	acc := q
	var a0, a1 fields_bn254.E2
	acc, a0, a1 = c.doubleStep(acc)
	setLine(0, n-2, a0, a1)
	a0, a1 = c.lineCompute(acc, q)
	setLine(1, n-3, a0, a1)
	acc, a0, a1 = c.addStep(acc, q)
	setLine(0, n-3, a0, a1)
	for i := n - 4; i >= 0; i-- {
		switch loopCounter[i] {
		case 0:
			acc, a0, a1 = c.doubleStep(acc)
			setLine(0, i, a0, a1)
		case 1, -1:
			var b0, b1 fields_bn254.E2
			acc, a0, a1, b0, b1 = c.doubleAndAddStep(acc, q, loopCounter[i] == -1)
			setLine(0, i, a0, a1)
			setLine(1, i, b0, b1)
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}
	}

	// Subgroup check on the ladder endpoint acc == [6x₀+2]Q. A full
	// AssertIsOnG2 here would redo an [x₀]Q scalar multiplication on top of
	// the ladder; the short-vector relation gets the same assurance from
	// the endpoint the ladder already computed.
	psiQ := c.psi(q)
	psi2Q := c.phi(q)
	psi3Q := c.psi(psi2Q)
	lhs := c.addTwist(c.addTwist(acc, psiQ), psi3Q)
	c.ext2.AssertIsEqual(&lhs.X, &psi2Q.X)
	c.ext2.AssertIsEqual(&lhs.Y, &psi2Q.Y)

	// the two extra lines through π(Q) and -π²(Q)
	q1 := &g2Point{
		X: *c.ext2.MulByNonResidue1Power2(c.ext2.Conjugate(&q.X)),
		Y: *c.ext2.MulByNonResidue1Power3(c.ext2.Conjugate(&q.Y)),
	}
	q2 := &g2Point{
		X: *c.ext2.MulByNonResidue2Power2(&q.X),
		Y: *c.ext2.MulByNonResidue2Power3(&q.Y),
	}

	acc, a0, a1 = c.addStep(acc, q1)
	setLine(0, n-1, a0, a1)
	a0, a1 = c.lineCompute(acc, q2)
	setLine(1, n-1, a0, a1)
	return lines
}

// Endomorphism constants for the subgroup check, same values as gnark's G2
// (sw_bn254/g2.go NewG2): w is the cubic root of unity scaling φ, u and v
// scale the two coordinates of ψ.
var (
	twistW   = "21888242871839275220042445260109153167277707414472061641714758635765020556616"
	twistUA0 = "21575463638280843010398324269430826099269044274347216827212613867836435027261"
	twistUA1 = "10307601595873709700152284273816112264069230130616436755625194854815875713954"
	twistVA0 = "2821565182194536844548159561693502659359617185244120367078079554186484126554"
	twistVA1 = "3505843767911556378687030309984248845540243509899259641013678093033130930403"
)

// phi maps q through φ (so φ(q) == ψ²(q)): x ↦ w·x, y ↦ -y.
// Mirrors gnark's G2.phi.
func (c *curve) phi(q *g2Point) *g2Point {
	x := c.ext2.MulByElement(&q.X, c.fp.NewElement(twistW))
	return &g2Point{X: *x, Y: *c.ext2.Neg(&q.Y)}
}

// psi maps q through ψ: x ↦ u·x̄, y ↦ v·ȳ.
// Mirrors gnark's G2.psi.
func (c *curve) psi(q *g2Point) *g2Point {
	u := &fields_bn254.E2{A0: *c.fp.NewElement(twistUA0), A1: *c.fp.NewElement(twistUA1)}
	v := &fields_bn254.E2{A0: *c.fp.NewElement(twistVA0), A1: *c.fp.NewElement(twistVA1)}
	x := c.ext2.Mul(c.ext2.Conjugate(&q.X), u)
	y := c.ext2.Mul(c.ext2.Conjugate(&q.Y), v)
	return &g2Point{X: *x, Y: *y}
}

// addTwist adds p1 and p2 on the twist. Mirrors gnark's G2.add: incomplete
// affine addition, like the ladder's addStep without the line evaluation.
func (c *curve) addTwist(p1, p2 *g2Point) *g2Point {
	// λ = (y2-y1)/(x2-x1)
	λ := c.ext2.DivUnchecked(c.ext2.Sub(&p2.Y, &p1.Y), c.ext2.Sub(&p2.X, &p1.X))

	// xr = λ²-x1-x2
	xr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	xr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr)-y1
	d := c.ext2.Sub(&p1.X, xr)
	yr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}
}

// doubleAndAddStep doubles p1 and adds (or subtracts, when isSub) p2, and
// evaluates the lines through p1 and ±p2 and through p1 and p1±p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (c *curve) doubleAndAddStep(p1, p2 *g2Point, isSub bool) (*g2Point, fields_bn254.E2, fields_bn254.E2, fields_bn254.E2, fields_bn254.E2) {
	// λ1 = (y1∓y2)/(x1-x2)
	var num *fields_bn254.E2
	if isSub {
		num = c.ext2.Add(&p1.Y, &p2.Y)
	} else {
		num = c.ext2.Sub(&p1.Y, &p2.Y)
	}
	λ1 := c.divE2WithZeroGuard(num, c.ext2.Sub(&p1.X, &p2.X))

	// x3 = λ1²-x1-x2; y3 is not needed
	x30 := c.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	x31 := c.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	x3 := &fields_bn254.E2{A0: *x30, A1: *x31}

	// λ2 = -λ1-2y1/(x3-x1)
	λ2 := c.divE2WithZeroGuard(c.ext2.MulByConstElement(&p1.Y, big.NewInt(2)), c.ext2.Sub(x3, &p1.X))
	λ2 = c.ext2.Neg(c.ext2.Add(λ2, λ1))

	// x4 = λ2²-x1-x3
	x40 := c.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p1.X.A0}, {x30}}, []int{1, -1, -1, -1})
	x41 := c.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p1.X.A1}, {x31}}, []int{2, -1, -1})
	x4 := &fields_bn254.E2{A0: *x40, A1: *x41}

	// y4 = λ2(x1-x4)-y1
	d := c.ext2.Sub(&p1.X, x4)
	y40 := c.fp.Eval([][]*baseEl{{&λ2.A0, &d.A0}, {&λ2.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	y41 := c.fp.Eval([][]*baseEl{{&λ2.A0, &d.A1}, {&λ2.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0a, r1a := c.lineThrough(λ1, p1)
	r0b, r1b := c.lineThrough(λ2, p1)
	return &g2Point{X: *x4, Y: fields_bn254.E2{A0: *y40, A1: *y41}}, r0a, r1a, r0b, r1b
}

// doubleStep doubles p1 and evaluates the tangent line at p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (c *curve) doubleStep(p1 *g2Point) (*g2Point, fields_bn254.E2, fields_bn254.E2) {
	// λ = 3x²/2y
	λ := c.divE2WithZeroGuard(
		c.ext2.MulByConstElement(c.ext2.Square(&p1.X), big.NewInt(3)),
		c.ext2.MulByConstElement(&p1.Y, big.NewInt(2)),
	)

	// xr = λ²-2x
	xr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}}, []int{1, -1, -2})
	xr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}}, []int{2, -2})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x-xr)-y
	d := c.ext2.Sub(&p1.X, xr)
	yr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0, r1 := c.lineThrough(λ, p1)
	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, r0, r1
}

// addStep adds p1 and p2 and evaluates the line through them.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (c *curve) addStep(p1, p2 *g2Point) (*g2Point, fields_bn254.E2, fields_bn254.E2) {
	// λ = (y2-y1)/(x2-x1)
	λ := c.divE2WithZeroGuard(c.ext2.Sub(&p2.Y, &p1.Y), c.ext2.Sub(&p2.X, &p1.X))

	// xr = λ²-x1-x2
	xr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	xr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr)-y1
	d := c.ext2.Sub(&p1.X, xr)
	yr0 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := c.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0, r1 := c.lineThrough(λ, p1)
	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, r0, r1
}

// lineCompute evaluates the line through p1 and p2 without computing p1+p2.
func (c *curve) lineCompute(p1, p2 *g2Point) (fields_bn254.E2, fields_bn254.E2) {
	// λ = (y2+y1)/(x1-x2)
	λ := c.divE2WithZeroGuard(c.ext2.Add(&p1.Y, &p2.Y), c.ext2.Sub(&p1.X, &p2.X))
	return c.lineThrough(λ, p1)
}

// lineThrough returns the line of slope λ through p: R0 = λ, R1 = λ·x - y.
func (c *curve) lineThrough(λ *fields_bn254.E2, p *g2Point) (fields_bn254.E2, fields_bn254.E2) {
	return *λ, fields_bn254.E2{
		A0: *c.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A0}, {&λ.A1, &p.X.A1}, {&p.Y.A0}}, []int{1, -1, -1}),
		A1: *c.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A1}, {&λ.A1, &p.X.A0}, {&p.Y.A1}}, []int{1, 1, -1}),
	}
}

// divE2WithZeroGuard computes n/d as a line slope, but for d == 0 it returns 0
// with the quotient constrained to 0 rather than left as a free hint value. A
// plain DivUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0, which leaves λ
// unconstrained -- the soundness gap when the point at infinity (0,0) reaches
// the Miller loop and every affine line evaluation becomes 0/0.
func (c *curve) divE2WithZeroGuard(n, d *fields_bn254.E2) *fields_bn254.E2 {
	dIsZero := c.ext2.IsZero(d)
	dSafe := c.ext2.Select(dIsZero, c.ext2.One(), d)
	return c.ext2.Select(dIsZero, c.ext2.Zero(), c.ext2.DivUnchecked(n, dSafe))
}
