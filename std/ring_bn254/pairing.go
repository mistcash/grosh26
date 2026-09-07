package ring_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/mistcash/grosh26"

	"github.com/consensys/gnark/std/math/emulated"
)

// Points, the 𝔽p¹² target group and the witness constructors are gnark's.
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

// lineEvaluation is a sparse 𝔽p¹² element: the line 1 + R0(x/y) + R1(1/y).
type lineEvaluation struct {
	R0, R1 fields_bn254.E2
}

// lineEvaluations holds, per Miller loop iteration, the one or two lines that
// iteration evaluates.
type lineEvaluations [2][len(bn254.LoopCounter)]*lineEvaluation

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
// It checks that the Qᵢ are in the correct subgroup, but not the Pᵢ; see
// [Pairing.AssertIsOnG1].
func (pr *Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	lines, err := pr.linesFor(Q)
	if err != nil {
		return nil, err
	}
	res, err := pr.millerLoopLines(P, lines, nil, nil)
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

// PairingCheck asserts ∏ᵢ e(Pᵢ, Qᵢ) == 1 with every point taken from the
// witness. It is [Pairing.PairingCheckPairs] over [NewPair] pairs; when some
// of the points are already known when the circuit is built, build the pairs
// with [Pairing.NewFixedQPair] or [Pairing.NewFixedPair] and call that
// directly.
//
// It checks that the Qᵢ are in the correct subgroup, but not the Pᵢ; see
// [Pairing.AssertIsOnG1].
func (pr *Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	if len(P) == 0 || len(P) != len(Q) {
		return errors.New("invalid inputs sizes")
	}
	pairs := make([]Pair, len(P))
	for i := range P {
		pairs[i] = NewPair(P[i], Q[i])
	}
	return pr.PairingCheckPairs(pairs...)
}

// PairingCheckPairs asserts ∏ᵢ e(Pᵢ, Qᵢ) == 1 over [Pair] values of any
// mix of shapes, following Section 4 of [On Proving Pairings]: instead of a
// final exponentiation, the prover supplies a residue witness and the check
// folds it into the Miller loop.
//
// Pairs whose G2 point comes from the witness are subgroup-checked in the
// circuit; the fixed ones were checked when they were built. The G1 points
// are not checked either way, see [Pairing.AssertIsOnG1].
//
// At least one pair has to be one the Miller loop runs over: a product of
// nothing but [Pairing.NewFixedPair] pairs is itself a constant, so the check
// would constrain nothing.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing) PairingCheckPairs(pairs ...Pair) error {
	if len(pairs) == 0 {
		return errors.New("invalid inputs sizes")
	}
	for i := range pairs {
		if pairs[i].p == nil || pairs[i].q == nil {
			return fmt.Errorf("pair %d is the zero Pair; build it with NewPair, NewFixedQPair or NewFixedPair", i)
		}
	}

	// hint the non-residue witness. Every pair feeds it, the fixed ones
	// included: the witness is the residue of the whole product, so a pair
	// folded in as a constant Miller loop value still has to be part of what
	// the hint is drawn from.
	inputs := make([]*baseEl, 0, 6*len(pairs))
	for i := range pairs {
		inputs = append(inputs, &pairs[i].p.X, &pairs[i].p.Y)
	}
	for i := range pairs {
		q := pairs[i].q
		inputs = append(inputs, &q.P.X.A0, &q.P.X.A1, &q.P.Y.A0, &q.P.Y.A1)
	}
	hint, err := pr.fp.NewHint(pairingCheckHint, 18, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	residueWitnessInv := pr.FromTower([12]*baseEl{hint[0], hint[1], hint[2], hint[3], hint[4], hint[5], hint[6], hint[7], hint[8], hint[9], hint[10], hint[11]})
	residueWitnessInvPoly := pr.ToPoly(residueWitnessInv)

	// InversePoly constrains the hint to be invertible, so the all-zero witness
	// -- which would satisfy the homogeneous check below for any input -- is
	// ruled out. The inverse is needed below anyway, for the q² Frobenius.
	residueWitness := pr.PolyToE12(pr.InversePoly(residueWitnessInvPoly))

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

	// Split the pairs: the ones the Miller loop runs over, and the ones whose
	// whole Miller loop value is already a constant.
	loopP := make([]*G1Affine, 0, len(pairs))
	loopLines := make([]lineEvaluations, 0, len(pairs))
	constants := make([]*basePoly, 0, len(pairs))
	for i := range pairs {
		if pairs[i].millerLoop != nil {
			constants = append(constants, pairs[i].millerLoop)
			continue
		}
		loopP = append(loopP, pairs[i].p)
		if pairs[i].lines != nil {
			loopLines = append(loopLines, *pairs[i].lines)
		} else {
			loopLines = append(loopLines, pr.computeLines(pairs[i].q))
		}
	}
	if len(loopP) == 0 {
		return errors.New("every pair is fully fixed: the product is a constant and the check constrains nothing")
	}

	res, err := pr.millerLoopLines(loopP, loopLines, residueWitnessInvPoly, pr.ToPoly(residueWitness))
	if err != nil {
		return fmt.Errorf("miller loop: %w", err)
	}

	// A fixed pair's Miller loop value is a plain factor on the product, so it
	// goes in here rather than seeding the accumulator: the loop's squarings
	// would otherwise raise it along with everything else.
	for _, c := range constants {
		res.Mul(c)
	}

	// Check that res · cubicNonResiduePower · residueWitnessInv^λ' == 1, where
	// λ' = q³ - q² + q. res is already MillerLoop(P,Q) · residueWitnessInv^{6x₀+2}
	// because the loop was seeded with residueWitnessInv. Every factor goes into
	// the accumulator, so the whole tail is one more ring check.
	res.Mul(pr.ToPoly(&cubicNonResiduePower))
	res.Mul(pr.ToPoly(pr.FrobeniusCube(residueWitnessInv)))
	// residueWitnessInv^(-q²) is residueWitness^(q²)
	res.Mul(pr.ToPoly(pr.FrobeniusSquare(residueWitness)))
	res.Mul(pr.ToPoly(pr.Frobenius(residueWitnessInv)))

	pr.AssertIsEqual(pr.PolyToE12(res.Eval()), pr.One())

	return nil
}

// linesFor returns the line evaluations for each Q, computing them in-circuit
// when the caller has not cached any.
func (pr *Pairing) linesFor(Q []*G2Affine) ([]lineEvaluations, error) {
	if len(Q) == 0 {
		return nil, errors.New("invalid inputs sizes")
	}
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		lines[i] = pr.computeLines(Q[i])
	}
	return lines, nil
}

// millerLoopLines runs the loop over precomputed lines. init seeds the
// accumulator and is multiplied back in on every positive bit, initInv on every
// negative one; both are nil for a plain Miller loop.
func (pr *Pairing) millerLoopLines(P []*G1Affine, lines []lineEvaluations, init, initInv *basePoly) (*polyring.PolyRingAccumulator[emulated.BN254Fp], error) {
	n := len(P)
	if n == 0 || n != len(lines) {
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
		l := lines[k][half][i]
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

// computeLines runs the [6x₀+2]Q ladder and collects the line evaluations. Q is
// asserted to be on the twist and in the prime-order subgroup first, with
// gnark's check.
func (pr *Pairing) computeLines(Q *G2Affine) lineEvaluations {
	pr.g.AssertIsOnG2(Q)

	q := &g2Point{X: Q.P.X, Y: Q.P.Y}
	loopCounter := bn254.LoopCounter
	n := len(loopCounter)

	var cLines lineEvaluations
	acc := q
	acc, cLines[0][n-2] = pr.doubleStep(acc)
	cLines[1][n-3] = pr.lineCompute(acc, q)
	acc, cLines[0][n-3] = pr.addStep(acc, q)
	for i := n - 4; i >= 0; i-- {
		switch loopCounter[i] {
		case 0:
			acc, cLines[0][i] = pr.doubleStep(acc)
		case 1:
			acc, cLines[0][i], cLines[1][i] = pr.doubleAndAddStep(acc, q, false)
		case -1:
			acc, cLines[0][i], cLines[1][i] = pr.doubleAndAddStep(acc, q, true)
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}
	}

	// the two extra lines through π(Q) and -π²(Q)
	q1 := &g2Point{
		X: *pr.ext2.MulByNonResidue1Power2(pr.ext2.Conjugate(&q.X)),
		Y: *pr.ext2.MulByNonResidue1Power3(pr.ext2.Conjugate(&q.Y)),
	}
	q2 := &g2Point{
		X: *pr.ext2.MulByNonResidue2Power2(&q.X),
		Y: *pr.ext2.MulByNonResidue2Power3(&q.Y),
	}

	acc, cLines[0][n-1] = pr.addStep(acc, q1)
	cLines[1][n-1] = pr.lineCompute(acc, q2)

	return cLines
}

// doubleAndAddStep doubles p1 and adds (or subtracts, when isSub) p2, and
// evaluates the lines through p1 and ±p2 and through p1 and p1±p2.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleAndAddStep(p1, p2 *g2Point, isSub bool) (*g2Point, *lineEvaluation, *lineEvaluation) {
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

	return &g2Point{X: *x4, Y: fields_bn254.E2{A0: *y40, A1: *y41}},
		pr.lineThrough(λ1, p1), pr.lineThrough(λ2, p1)
}

// doubleStep doubles p1 and evaluates the tangent line at p1.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) doubleStep(p1 *g2Point) (*g2Point, *lineEvaluation) {
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

	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, pr.lineThrough(λ, p1)
}

// addStep adds p1 and p2 and evaluates the line through them.
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func (pr *Pairing) addStep(p1, p2 *g2Point) (*g2Point, *lineEvaluation) {
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

	return &g2Point{X: *xr, Y: fields_bn254.E2{A0: *yr0, A1: *yr1}}, pr.lineThrough(λ, p1)
}

// lineCompute evaluates the line through p1 and p2 without computing p1+p2.
func (pr *Pairing) lineCompute(p1, p2 *g2Point) *lineEvaluation {
	// λ = (y2+y1)/(x1-x2)
	λ := pr.divE2WithZeroGuard(pr.ext2.Add(&p1.Y, &p2.Y), pr.ext2.Sub(&p1.X, &p2.X))
	return pr.lineThrough(λ, p1)
}

// lineThrough returns the line of slope λ through p: R0 = λ, R1 = λ·x - y.
func (pr *Pairing) lineThrough(λ *fields_bn254.E2, p *g2Point) *lineEvaluation {
	return &lineEvaluation{
		R0: *λ,
		R1: fields_bn254.E2{
			A0: *pr.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A0}, {&λ.A1, &p.X.A1}, {&p.Y.A0}}, []int{1, -1, -1}),
			A1: *pr.fp.Eval([][]*baseEl{{&λ.A0, &p.X.A1}, {&λ.A1, &p.X.A0}, {&p.Y.A1}}, []int{1, 1, -1}),
		},
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
