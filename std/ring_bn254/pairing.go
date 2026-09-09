package ring_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/mistcash/grosh26/std/polyring"

	"github.com/consensys/gnark/std/math/emulated"
)

// Points, the 𝔽p¹² target group and the witness constructors are gnark's.
// Build witness points with sw_bn254.NewG1Affine / NewG2Affine and fixed
// points with sw_bn254.NewG2AffineFixed: a Q carrying Lines skips the ladder.
type (
	G1Affine = sw_bn254.G1Affine
	G2Affine = sw_bn254.G2Affine
	GTEl     = sw_bn254.GTEl
)

// accumulatorTargetDegree caps the degree of a product queued in the ring
// accumulator before it is collapsed into one deferred check. A Miller loop
// iteration squares the running value (degree 22) and multiplies in line
// evaluations of degree 9, so 69 fits a squaring plus five lines.
const accumulatorTargetDegree = 69

// g2Point is an affine point on the BN254 twist. gnark's own G2 point type is
// unexported, so the Miller loop's ladder uses this one and converts at the
// G2Affine boundary.
type g2Point struct {
	X, Y fields_bn254.E2
}

// Pairing computes the BN254 pairing with the 𝔽p¹² products evaluated in the
// polynomial ring. Point arithmetic, subgroup checks, the Frobenius maps and
// the residue witness hint all come from gnark; what is different is the Miller
// loop accumulation, which queues line evaluations as ring products instead of
// reducing each one with a sparse multiplication.
type Pairing struct {
	*Ext12
	ext2 *fields_bn254.Ext2
	fp   *curveF
	g    *sw_bn254.Pairing
}

// NewPairing returns a pairing context sharing api's emulated field.
func NewPairing(api frontend.API) (*Pairing, error) {
	// the ring checker has to be registered before anything creates an emulated
	// field, see [NewExt12]
	ext12 := NewExt12(api)
	g, err := sw_bn254.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new gnark pairing: %w", err)
	}
	return &Pairing{
		Ext12: ext12,
		ext2:  fields_bn254.NewExt2(api),
		fp:    ext12.fp,
		g:     g,
	}, nil
}

// AssertIsOnG1 asserts P is on the curve and in the prime-order subgroup.
func (pr *Pairing) AssertIsOnG1(P *G1Affine) { pr.g.AssertIsOnG1(P) }

// AssertIsOnG2 asserts Q is on the twist and in the prime-order subgroup.
func (pr *Pairing) AssertIsOnG2(Q *G2Affine) { pr.g.AssertIsOnG2(Q) }

// MillerLoop computes the multi-Miller loop
//
//	∏ᵢ { fᵢ_{6x₀+2,Q}(P) · ℓᵢ_{[6x₀+2]Q,π(Q)}(P) · ℓᵢ_{[6x₀+2]Q+π(Q),-π²(Q)}(P) }
//
// A Q with precomputed lines (sw_bn254.NewG2AffineFixed) skips the ladder and
// the subgroup check; the rest run them in-circuit. It checks the witness Qᵢ
// subgroup, but not the Pᵢ; see [Pairing.AssertIsOnG1].
func (pr *Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	if len(P) == 0 || len(P) != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}
	for i := range Q {
		if P[i] == nil || Q[i] == nil {
			return nil, fmt.Errorf("pair %d is nil", i)
		}
		if Q[i].Lines == nil {
			pr.computeLines(Q[i])
		}
	}
	res, err := pr.millerLoopLines(P, Q, nil, nil)
	if err != nil {
		return nil, err
	}
	return pr.PolyToE12(res.Eval()), nil
}

// Pair computes the reduced pairing ∏ᵢ e(Pᵢ, Qᵢ).
func (pr *Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	return pr.g.FinalExponentiation(res), nil
}

// PairingCheck asserts ∏ᵢ e(Pᵢ, Qᵢ) == 1 following Section 4 of
// [On Proving Pairings]: instead of a final exponentiation, the prover
// supplies a residue witness and the check folds it into the Miller loop.
//
// A Q with precomputed lines (sw_bn254.NewG2AffineFixed) skips the ladder and
// the subgroup check; the rest run them in-circuit. An optional previous
// Miller loop value is folded in as one factor instead of a pass through the
// loop (cf. gnark's MillerLoopAndMul); it must be raw MillerLoopFixedQ
// output, not a reduced pairing. The G1 points are not checked either way,
// see [Pairing.AssertIsOnG1].
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine, previous *GTEl) error {
	if len(P) == 0 || len(P) != len(Q) {
		return errors.New("invalid inputs sizes")
	}
	for i := range P {
		if P[i] == nil || Q[i] == nil {
			return fmt.Errorf("pair %d is nil", i)
		}
	}

	inputs := make([]*baseEl, 0, 6*len(P))
	for i := range P {
		inputs = append(inputs, &P[i].X, &P[i].Y)
	}
	for i := range Q {
		q := Q[i]
		inputs = append(inputs, &q.P.X.A0, &q.P.X.A1, &q.P.Y.A0, &q.P.Y.A1)
	}
	checkHint := pairingCheckHint
	if previous != nil {
		// the residue covers the whole product, so previous travels with
		// the points as its tower limbs.
		tower := pr.ToTower(previous)
		inputs = append(inputs, tower[:]...)
		checkHint = millerLoopAndCheckFinalExpHint
	}
	hint, err := pr.fp.NewHint(checkHint, 18, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	// InversePoly constrains the hint to be invertible, ruling out the
	// all-zero witness that would satisfy the check below for any input.
	// The two hints return different first outputs: pairingCheckHint gives
	// the inverse witness, millerLoopAndCheckFinalExpHint the witness itself.
	var residueWitness *E12
	var residueWitnessInvPoly *basePoly
	if previous != nil {
		residueWitness = pr.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})
		residueWitnessInvPoly = pr.InversePoly(pr.ToPoly(residueWitness))
	} else {
		residueWitnessInvPoly = pr.ToPoly(pr.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]}))
		residueWitness = pr.PolyToE12(pr.InversePoly(residueWitnessInvPoly))
	}
	residueWitnessInv := pr.PolyToE12(residueWitnessInvPoly)

	// constrain cubicNonResiduePower to be in 𝔽p⁶, that is
	// a100 = a101 = a110 = a111 = a120 = a121 = 0
	nine := big.NewInt(9)
	zero := pr.fp.Zero()
	cubicNonResiduePower := GTEl{
		A0:  *pr.fp.Sub(hint[12], pr.fp.MulConst(hint[13], nine)),
		A1:  *zero,
		A2:  *pr.fp.Sub(hint[14], pr.fp.MulConst(hint[15], nine)),
		A3:  *zero,
		A4:  *pr.fp.Sub(hint[16], pr.fp.MulConst(hint[17], nine)),
		A5:  *zero,
		A6:  *hint[13],
		A7:  *zero,
		A8:  *hint[15],
		A9:  *zero,
		A10: *hint[17],
		A11: *zero,
	}

	for i := range Q {
		if Q[i].Lines == nil {
			pr.computeLines(Q[i])
		}
	}
	res, err := pr.millerLoopLines(P, Q, residueWitnessInvPoly, pr.ToPoly(residueWitness))
	if err != nil {
		return fmt.Errorf("miller loop: %w", err)
	}

	// Check that res · previous · cubicNonResiduePower · residueWitnessInv^λ' == 1,
	// where λ' = q³ - q² + q. res is already MillerLoop(P,Q) · residueWitnessInv^{6x₀+2}
	// because the loop was seeded with residueWitnessInv. Every factor goes into
	// the accumulator, so the whole tail is one more ring check.
	res.Mul(pr.ToPoly(&cubicNonResiduePower))
	res.Mul(pr.ToPoly(pr.FrobeniusCube(residueWitnessInv)))
	// residueWitnessInv^(-q²) is residueWitness^(q²)
	res.Mul(pr.ToPoly(pr.FrobeniusSquare(residueWitness)))
	res.Mul(pr.ToPoly(pr.Frobenius(residueWitnessInv)))

	prod := pr.PolyToE12(res.Eval())
	if previous != nil {
		// A previous value is a plain factor: the loop's squarings would
		// otherwise raise it along with everything else. This uses gnark's
		// E12 arithmetic, not the ring: the ring reads raw limbs, which
		// ValueOf constants only gain on their first genuine field op.
		prod = pr.Ext12.Ext12.Mul(prod, previous)
	}

	pr.AssertIsEqual(prod, pr.One())

	return nil
}

// millerLoopLines runs the loop over Q's lines -- precomputed off-circuit
// where set, computed in-circuit above otherwise. init seeds the accumulator
// and is multiplied back in on every positive bit, initInv on every negative
// one; both are nil for a plain Miller loop.
func (pr *Pairing) millerLoopLines(P []*G1Affine, Q []*G2Affine, init, initInv *basePoly) (*polyring.PolyRingAccumulator[emulated.BN254Fp], error) {
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	// precomputations. A point at infinity has y = 0, whose inverse is
	// undefined, so yInv is forced to 0 there.
	yInv := make([]*baseEl, n)
	xNegOverY := make([]*baseEl, n)
	for k := 0; k < n; k++ {
		isYZero := pr.fp.IsZero(&P[k].Y)
		y := pr.fp.Select(isYZero, pr.fp.One(), &P[k].Y)
		yInv[k] = pr.fp.Select(isYZero, pr.fp.Zero(), pr.fp.Inverse(y))
		xNegOverY[k] = pr.fp.Neg(pr.fp.Mul(&P[k].X, yInv[k]))
	}

	// line k of iteration i, evaluated at P[k]
	line := func(k, half, i int) *basePoly {
		l := (*Q[k].Lines)[half][i]
		return pr.ToPoly01379(
			pr.ext2.MulByElement(&l.R0, xNegOverY[k]),
			pr.ext2.MulByElement(&l.R1, yInv[k]),
		)
	}

	// Compute f_{6x₀+2,Q}(P)
	res := pr.NewAccumulator(accumulatorTargetDegree)
	if init != nil {
		if initInv == nil {
			return nil, errors.New("initInv cannot be nil when init is not nil")
		}
		pr.ToCommit(init, initInv)
		res.Mul(init)
	}

	loopCounter := bn254.LoopCounter
	for i := len(loopCounter) - 2; i >= 0; i-- {
		res.Sqr()

		switch loopCounter[i] {
		case 0:
			for k := 0; k < n; k++ {
				res.Mul(line(k, 0, i))
			}
		case 1, -1:
			if init != nil {
				// multiply by init on a positive bit, by its inverse on a negative one
				if loopCounter[i] == 1 {
					res.Mul(init)
				} else {
					res.Mul(initInv)
				}
			}
			for k := 0; k < n; k++ {
				res.Mul(line(k, 0, i)).Mul(line(k, 1, i))
			}
		default:
			return nil, fmt.Errorf("invalid loop counter value %d", loopCounter[i])
		}

		// collapse the iteration into a single ring check, so the accumulated
		// degree stays bounded whatever n is
		res.Eval()
	}

	// ℓ_{[6x₀+2]Q,π(Q)}(P) · ℓ_{[6x₀+2]Q+π(Q),-π²(Q)}(P)
	last := len(loopCounter) - 1
	for k := 0; k < n; k++ {
		res.Mul(line(k, 0, last)).Mul(line(k, 1, last))
	}

	return res, nil
}

// computeLines runs the [6x₀+2]Q ladder and stores the line evaluations in
// Q.Lines. Q is asserted to be on the twist first, with gnark's check; the
// prime-order subgroup check then reuses the ladder endpoint instead of a
// separate scalar multiplication, exactly like gnark's own computeLines:
// [6x₀+2]Q + ψ(Q) + ψ³(Q) == ψ²(Q), see Sec. 3.1.2 (Remark 2) of
// https://eprint.iacr.org/2022/348.
func (pr *Pairing) computeLines(Q *G2Affine) {
	pr.g.AssertIsOnTwist(Q)

	Q.Lines = sw_bn254.NewG2AffineFixedPlaceholder().Lines

	q := &g2Point{X: Q.P.X, Y: Q.P.Y}
	loopCounter := bn254.LoopCounter
	n := len(loopCounter)

	setLine := func(half, i int, r0, r1 fields_bn254.E2) {
		(*Q.Lines)[half][i].R0 = r0
		(*Q.Lines)[half][i].R1 = r1
	}

	acc := q
	var a0, a1 fields_bn254.E2
	acc, a0, a1 = pr.doubleStep(acc)
	setLine(0, n-2, a0, a1)
	a0, a1 = pr.lineCompute(acc, q)
	setLine(1, n-3, a0, a1)
	acc, a0, a1 = pr.addStep(acc, q)
	setLine(0, n-3, a0, a1)
	for i := n - 4; i >= 0; i-- {
		switch loopCounter[i] {
		case 0:
			acc, a0, a1 = pr.doubleStep(acc)
			setLine(0, i, a0, a1)
		case 1, -1:
			var b0, b1 fields_bn254.E2
			acc, a0, a1, b0, b1 = pr.doubleAndAddStep(acc, q, loopCounter[i] == -1)
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
	psiQ := pr.psi(q)
	psi2Q := pr.phi(q)
	psi3Q := pr.psi(psi2Q)
	lhs := pr.addTwist(pr.addTwist(acc, psiQ), psi3Q)
	pr.ext2.AssertIsEqual(&lhs.X, &psi2Q.X)
	pr.ext2.AssertIsEqual(&lhs.Y, &psi2Q.Y)

	// the two extra lines through π(Q) and -π²(Q)
	q1 := &g2Point{
		X: *pr.ext2.MulByNonResidue1Power2(pr.ext2.Conjugate(&q.X)),
		Y: *pr.ext2.MulByNonResidue1Power3(pr.ext2.Conjugate(&q.Y)),
	}
	q2 := &g2Point{
		X: *pr.ext2.MulByNonResidue2Power2(&q.X),
		Y: *pr.ext2.MulByNonResidue2Power3(&q.Y),
	}

	acc, a0, a1 = pr.addStep(acc, q1)
	setLine(0, n-1, a0, a1)
	a0, a1 = pr.lineCompute(acc, q2)
	setLine(1, n-1, a0, a1)
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
func (pr *Pairing) phi(q *g2Point) *g2Point {
	x := pr.ext2.MulByElement(&q.X, pr.fp.NewElement(twistW))
	return &g2Point{X: *x, Y: *pr.ext2.Neg(&q.Y)}
}

// psi maps q through ψ: x ↦ u·x̄, y ↦ v·ȳ.
// Mirrors gnark's G2.psi.
func (pr *Pairing) psi(q *g2Point) *g2Point {
	u := &fields_bn254.E2{A0: *pr.fp.NewElement(twistUA0), A1: *pr.fp.NewElement(twistUA1)}
	v := &fields_bn254.E2{A0: *pr.fp.NewElement(twistVA0), A1: *pr.fp.NewElement(twistVA1)}
	x := pr.ext2.Mul(pr.ext2.Conjugate(&q.X), u)
	y := pr.ext2.Mul(pr.ext2.Conjugate(&q.Y), v)
	return &g2Point{X: *x, Y: *y}
}

// addTwist adds p1 and p2 on the twist. Mirrors gnark's G2.add: incomplete
// affine addition, like the ladder's addStep without the line evaluation.
func (pr *Pairing) addTwist(p1, p2 *g2Point) *g2Point {
	// λ = (y2-y1)/(x2-x1)
	λ := pr.ext2.DivUnchecked(pr.ext2.Sub(&p2.Y, &p1.Y), pr.ext2.Sub(&p2.X, &p1.X))

	// xr = λ²-x1-x2
	xr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	xr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr)-y1
	d := pr.ext2.Sub(&p1.X, xr)
	yr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}
}

// doubleAndAddStep doubles p1 and adds (or subtracts, when isSub) p2, and
// evaluates the lines through p1 and ±p2 and through p1 and p1±p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleAndAddStep(p1, p2 *g2Point, isSub bool) (*g2Point, fields_bn254.E2, fields_bn254.E2, fields_bn254.E2, fields_bn254.E2) {
	// λ1 = (y1∓y2)/(x1-x2)
	var num *fields_bn254.E2
	if isSub {
		num = pr.ext2.Add(&p1.Y, &p2.Y)
	} else {
		num = pr.ext2.Sub(&p1.Y, &p2.Y)
	}
	λ1 := pr.divE2WithZeroGuard(num, pr.ext2.Sub(&p1.X, &p2.X))

	// x3 = λ1²-x1-x2; y3 is not needed
	x30 := pr.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A0}, {&λ1.A1, &λ1.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	x31 := pr.fp.Eval([][]*baseEl{{&λ1.A0, &λ1.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	x3 := &fields_bn254.E2{A0: *x30, A1: *x31}

	// λ2 = -λ1-2y1/(x3-x1)
	λ2 := pr.divE2WithZeroGuard(pr.ext2.MulByConstElement(&p1.Y, big.NewInt(2)), pr.ext2.Sub(x3, &p1.X))
	λ2 = pr.ext2.Neg(pr.ext2.Add(λ2, λ1))

	// x4 = λ2²-x1-x3
	x40 := pr.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A0}, {&λ2.A1, &λ2.A1}, {&p1.X.A0}, {x30}}, []int{1, -1, -1, -1})
	x41 := pr.fp.Eval([][]*baseEl{{&λ2.A0, &λ2.A1}, {&p1.X.A1}, {x31}}, []int{2, -1, -1})
	x4 := &fields_bn254.E2{A0: *x40, A1: *x41}

	// y4 = λ2(x1-x4)-y1
	d := pr.ext2.Sub(&p1.X, x4)
	y40 := pr.fp.Eval([][]*baseEl{{&λ2.A0, &d.A0}, {&λ2.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	y41 := pr.fp.Eval([][]*baseEl{{&λ2.A0, &d.A1}, {&λ2.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0a, r1a := pr.lineThrough(λ1, p1)
	r0b, r1b := pr.lineThrough(λ2, p1)
	return &g2Point{X: *x4, Y: fields_bn254.E2{A0: *y40, A1: *y41}}, r0a, r1a, r0b, r1b
}

// doubleStep doubles p1 and evaluates the tangent line at p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleStep(p1 *g2Point) (*g2Point, fields_bn254.E2, fields_bn254.E2) {
	// λ = 3x²/2y
	λ := pr.divE2WithZeroGuard(
		pr.ext2.MulByConstElement(pr.ext2.Square(&p1.X), big.NewInt(3)),
		pr.ext2.MulByConstElement(&p1.Y, big.NewInt(2)),
	)

	// xr = λ²-2x
	xr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}}, []int{1, -1, -2})
	xr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}}, []int{2, -2})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x-xr)-y
	d := pr.ext2.Sub(&p1.X, xr)
	yr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0, r1 := pr.lineThrough(λ, p1)
	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, r0, r1
}

// addStep adds p1 and p2 and evaluates the line through them.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) addStep(p1, p2 *g2Point) (*g2Point, fields_bn254.E2, fields_bn254.E2) {
	// λ = (y2-y1)/(x2-x1)
	λ := pr.divE2WithZeroGuard(pr.ext2.Sub(&p2.Y, &p1.Y), pr.ext2.Sub(&p2.X, &p1.X))

	// xr = λ²-x1-x2
	xr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A0}, {&λ.A1, &λ.A1}, {&p1.X.A0}, {&p2.X.A0}}, []int{1, -1, -1, -1})
	xr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &λ.A1}, {&p1.X.A1}, {&p2.X.A1}}, []int{2, -1, -1})
	xr := &fields_bn254.E2{A0: *xr0, A1: *xr1}

	// yr = λ(x1-xr)-y1
	d := pr.ext2.Sub(&p1.X, xr)
	yr0 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A0}, {&λ.A1, &d.A1}, {&p1.Y.A0}}, []int{1, -1, -1})
	yr1 := pr.fp.Eval([][]*baseEl{{&λ.A0, &d.A1}, {&λ.A1, &d.A0}, {&p1.Y.A1}}, []int{1, 1, -1})

	r0, r1 := pr.lineThrough(λ, p1)
	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, r0, r1
}

// lineCompute evaluates the line through p1 and p2 without computing p1+p2.
func (pr *Pairing) lineCompute(p1, p2 *g2Point) (fields_bn254.E2, fields_bn254.E2) {
	// λ = (y2+y1)/(x1-x2)
	λ := pr.divE2WithZeroGuard(pr.ext2.Add(&p1.Y, &p2.Y), pr.ext2.Sub(&p1.X, &p2.X))
	return pr.lineThrough(λ, p1)
}

// lineThrough returns the line of slope λ through p: R0 = λ, R1 = λ·x - y.
func (pr *Pairing) lineThrough(λ *fields_bn254.E2, p *g2Point) (fields_bn254.E2, fields_bn254.E2) {
	return *λ, fields_bn254.E2{
		A0: *pr.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A0}, {&λ.A1, &p.X.A1}, {&p.Y.A0}}, []int{1, -1, -1}),
		A1: *pr.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A1}, {&λ.A1, &p.X.A0}, {&p.Y.A1}}, []int{1, 1, -1}),
	}
}

// divE2WithZeroGuard computes n/d as a line slope, but for d == 0 it returns 0
// with the quotient constrained to 0 rather than left as a free hint value. A
// plain DivUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0, which leaves λ
// unconstrained -- the soundness gap when the point at infinity (0,0) reaches
// the Miller loop and every affine line evaluation becomes 0/0.
func (pr *Pairing) divE2WithZeroGuard(n, d *fields_bn254.E2) *fields_bn254.E2 {
	dIsZero := pr.ext2.IsZero(d)
	dSafe := pr.ext2.Select(dIsZero, pr.ext2.One(), d)
	return pr.ext2.Select(dIsZero, pr.ext2.Zero(), pr.ext2.DivUnchecked(n, dSafe))
}
