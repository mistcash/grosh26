package ringpairing

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/polyring"
)

// accumulatorTargetDegree caps the degree of a product queued in the ring
// accumulator before it is collapsed into one deferred check. A Miller loop
// iteration squares the running value (degree 22) and multiplies in line
// evaluations of degree 8 or 9, so 69 fits a squaring plus five lines.
const accumulatorTargetDegree = 69

// G1Affine is a point on the curve over the emulated base field F.
type G1Affine[F emulated.FieldParams] = sw_emulated.AffinePoint[F]

// Line is one line of the Miller loop in gnark's form: R0 = λ, the slope, and
// R1 = λ·x - y for a point (x, y) on it, each an 𝔽p² element given as its two
// coefficients.
type Line[F emulated.FieldParams] struct {
	R0, R1 [2]*emulated.Element[F]
}

// Lines are a G2 point's lines, indexed [half][iteration] like gnark's: half 0
// holds the doubling line, half 1 the addition line of a non-zero digit.
type Lines[F emulated.FieldParams] [2][]*Line[F]

// NewLines returns empty lines for a loop of n iterations.
func NewLines[F emulated.FieldParams](n int) *Lines[F] {
	return &Lines[F]{make([]*Line[F], n), make([]*Line[F], n)}
}

// Curve is everything about a pairing-friendly curve the ring pairing needs
// beyond the ring itself: gnark's types, hints and 𝔽p¹² maps, the Miller loop's
// shape, and the twist with the ladder computing lines for a G2 point given as
// a witness.
type Curve[F emulated.FieldParams, G2El, GtEl any] interface {
	// Xi0 is the real part of the sextic non-residue ξ = ξ₀ + u.
	Xi0() int64
	// LoopCounter is the Miller loop's signed binary expansion, most
	// significant digit last; the loop starts at the second-to-last digit.
	LoopCounter() []int8
	// LineSlots are the powers of w a line 1 + R0·(-x/y) + R1·(1/y), evaluated
	// at P = (x, y), puts its three terms on; the 𝔽p² terms are embedded as
	// a0 + a1·u = (a0 - ξ₀a1)·wᵏ + a1·wᵏ⁺⁶.
	LineSlots() (one, r0, r1 int)
	// LastLines is the iteration index of lines applied after the loop, or -1
	// for none.
	LastLines() int
	// ConjugateMillerLoop reports whether the loop's raw value is conjugated
	// into the Miller loop value, as for a negative seed.
	ConjugateMillerLoop() bool

	// G2 returns Q's coordinates (x.A0, x.A1, y.A0, y.A1) and its precomputed
	// lines, or nil lines when Q carries none.
	G2(Q *G2El) ([4]*emulated.Element[F], *Lines[F])
	// ComputeLines runs the ladder for a witness Q, asserting Q is on G2.
	ComputeLines(Q *G2El) *Lines[F]
	AssertIsOnG1(P *G1Affine[F])
	AssertIsOnG2(Q *G2El)

	// Coeffs and FromCoeffs convert between GtEl and its direct-extension
	// coefficients; ToTower and FromTower between GtEl and gnark-crypto's tower.
	Coeffs(x *GtEl) [12]*emulated.Element[F]
	FromCoeffs(c [12]*emulated.Element[F]) *GtEl
	ToTower(x *GtEl) [12]*emulated.Element[F]
	FromTower(x [12]*emulated.Element[F]) *GtEl

	// InverseHint is gnark's 𝔽p¹² inverse hint, on direct-extension
	// coefficients.
	InverseHint() solver.Hint
	// CheckHint returns gnark's residue witness hint for a pairing check,
	// with or without a previous Miller loop value, and whether its first
	// output is the residue witness's inverse rather than the witness.
	CheckHint(withPrevious bool) (hint solver.Hint, givesInverse bool)
	// NeedsResidue reports whether the check needs the residue witness c
	// itself, not just c⁻¹.
	NeedsResidue() bool
	// ResidueTail returns the factors that complete c^(-λ) once the loop,
	// seeded with c⁻¹, has run. c is nil unless NeedsResidue.
	ResidueTail(c, cInv *GtEl) []*GtEl

	// Mul, Conjugate, FinalExponentiation and AssertIsEqual are gnark's
	// coefficient-wise 𝔽p¹² arithmetic.
	Mul(x, y *GtEl) *GtEl
	Conjugate(x *GtEl) *GtEl
	FinalExponentiation(x *GtEl) *GtEl
	AssertIsEqual(x, y *GtEl)
}

// Pairing computes pairings with the 𝔽p¹² products evaluated in the
// polynomial ring. Point arithmetic, subgroup checks, the Frobenius maps and
// the residue witness hints all come from gnark through the [Curve]; what is
// different is the Miller loop accumulation, which queues line evaluations as
// ring products instead of reducing each one with a sparse multiplication.
type Pairing[F emulated.FieldParams, G2El, GtEl any] struct {
	*ring[F]
	c Curve[F, G2El, GtEl]
}

// New returns a ring pairing over the curve newCurve builds. Curve packages
// wrap it in their own NewPairing.
//
// The ring checker is registered before newCurve runs: the ring checks emit
// range checks of their own, and gnark runs deferred callbacks in
// registration order, so the range checker -- created with the first emulated
// field -- has to be registered after the ring checker or it will already be
// closed by the time the ring checks run. Call New before anything else in
// the circuit creates an emulated field for the same reason.
func New[F emulated.FieldParams, G2El, GtEl any](api frontend.API, newCurve func(frontend.API) (Curve[F, G2El, GtEl], error)) (*Pairing[F, G2El, GtEl], error) {
	prc := polyring.NewPolyRingChecker[F](api)
	c, err := newCurve(api)
	if err != nil {
		return nil, err
	}
	return &Pairing[F, G2El, GtEl]{ring: newRing[F](prc, c.Xi0(), c.InverseHint()), c: c}, nil
}

// AssertIsOnG1 asserts P is on the curve and in the prime-order subgroup.
func (pr *Pairing[F, G2El, GtEl]) AssertIsOnG1(P *G1Affine[F]) { pr.c.AssertIsOnG1(P) }

// AssertIsOnG2 asserts Q is on the twist and in the prime-order subgroup.
func (pr *Pairing[F, G2El, GtEl]) AssertIsOnG2(Q *G2El) { pr.c.AssertIsOnG2(Q) }

// AssertIsEqual asserts x == y in 𝔽p¹².
func (pr *Pairing[F, G2El, GtEl]) AssertIsEqual(x, y *GtEl) { pr.c.AssertIsEqual(x, y) }

func (pr *Pairing[F, G2El, GtEl]) toPoly(x *GtEl) *poly[F] {
	c := pr.c.Coeffs(x)
	return &poly[F]{Coeffs: c[:]}
}

func (pr *Pairing[F, G2El, GtEl]) fromPoly(p *poly[F]) *GtEl {
	return pr.c.FromCoeffs([12]*emulated.Element[F](p.Coeffs))
}

// MillerLoop computes the multi-Miller loop ∏ᵢ fᵢ(Pᵢ, Qᵢ), the raw value
// gnark-crypto's MillerLoopFixedQ returns.
//
// A Q with precomputed lines (sw_*.NewG2AffineFixed) skips the ladder and
// the subgroup check; the rest run them in-circuit. It checks the witness Qᵢ
// subgroup, but not the Pᵢ; see [Pairing.AssertIsOnG1].
func (pr *Pairing[F, G2El, GtEl]) MillerLoop(P []*G1Affine[F], Q []*G2El) (*GtEl, error) {
	lines, err := pr.prepare(P, Q)
	if err != nil {
		return nil, err
	}
	res := pr.fromPoly(pr.millerLoopLines(P, lines, nil, nil).Eval())
	if pr.c.ConjugateMillerLoop() {
		res = pr.c.Conjugate(res)
	}
	return res, nil
}

// Pair computes the reduced pairing ∏ᵢ e(Pᵢ, Qᵢ).
func (pr *Pairing[F, G2El, GtEl]) Pair(P []*G1Affine[F], Q []*G2El) (*GtEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	return pr.c.FinalExponentiation(res), nil
}

// PairingCheck asserts ∏ᵢ e(Pᵢ, Qᵢ) == 1 following Section 4 of
// [On Proving Pairings]: instead of a final exponentiation, the prover
// supplies a residue witness and the check folds it into the Miller loop.
//
// A Q with precomputed lines (sw_*.NewG2AffineFixed) skips the ladder and
// the subgroup check; the rest run them in-circuit. An optional previous
// Miller loop value is folded in as one factor instead of a pass through the
// loop (cf. gnark's MillerLoopAndMul), in the form gnark's
// AssertMultiMillerLoopAndFinalExpIsOne takes it. The G1 points are not
// checked either way, see [Pairing.AssertIsOnG1].
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (pr *Pairing[F, G2El, GtEl]) PairingCheck(P []*G1Affine[F], Q []*G2El, previous *GtEl) error {
	lines, err := pr.prepare(P, Q)
	if err != nil {
		return err
	}

	inputs := make([]*emulated.Element[F], 0, 6*len(P)+12)
	for i := range P {
		inputs = append(inputs, &P[i].X, &P[i].Y)
	}
	for i := range Q {
		coords, _ := pr.c.G2(Q[i])
		inputs = append(inputs, coords[:]...)
	}
	if previous != nil {
		// the residue covers the whole product, so previous travels with
		// the points as its tower limbs.
		tower := pr.c.ToTower(previous)
		inputs = append(inputs, tower[:]...)
	}
	checkHint, givesInverse := pr.c.CheckHint(previous != nil)
	hint, err := pr.fp.NewHint(checkHint, 18, inputs...)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	// c is the residue witness, cInv its inverse. Whichever one the hint
	// returns is committed: it seeds the loop. Deriving the other with
	// [ring.inverse] constrains both invertible, ruling out the all-zero
	// witness that would satisfy the check for any input.
	var c, cInv *poly[F]
	w := pr.toPoly(pr.c.FromTower([12]*emulated.Element[F](hint[:12])))
	switch {
	case !givesInverse:
		c, cInv = w, pr.inverse(w)
	case pr.c.NeedsResidue():
		c, cInv = pr.inverse(w), w
	default:
		cInv = w
		pr.commitPoly(cInv)
	}

	// the scaling factor is constrained to 𝔽p⁶ by construction; its
	// coefficients come straight from the hint, so they are committed too.
	scaling := pr.fp6(hint[12:])
	pr.commit(hint[12:]...)

	res := pr.millerLoopLines(P, lines, cInv, c)

	// Check that res · scaling · tail == 1: res is already MillerLoop(P,Q)·c^(-x₀)
	// because the loop was seeded with c⁻¹, and the tail supplies the
	// Frobenius powers of c that complete c^(-λ). Every factor goes into the
	// accumulator, so the whole tail is one more ring check.
	res.Mul(scaling)
	var cGT *GtEl
	if c != nil {
		cGT = pr.fromPoly(c)
	}
	for _, f := range pr.c.ResidueTail(cGT, pr.fromPoly(cInv)) {
		res.Mul(pr.toPoly(f))
	}

	prod := pr.fromPoly(res.Eval())
	if previous != nil {
		// A previous value is a plain factor: the loop's squarings would
		// otherwise raise it along with everything else. This uses gnark's
		// E12 arithmetic, not the ring: the ring reads raw limbs, which
		// ValueOf constants only gain on their first genuine field op.
		prod = pr.c.Mul(prod, previous)
	}
	pr.assertIsOne(pr.toPoly(prod))
	return nil
}

// prepare validates the pairs, commits the points the ring products are
// built from and returns each Q's lines, running the ladder for those not
// carrying precomputed ones.
func (pr *Pairing[F, G2El, GtEl]) prepare(P []*G1Affine[F], Q []*G2El) ([]*Lines[F], error) {
	if len(P) == 0 || len(P) != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}
	lines := make([]*Lines[F], len(Q))
	for i := range P {
		if P[i] == nil || Q[i] == nil {
			return nil, fmt.Errorf("pair %d is nil", i)
		}
		pr.commit(&P[i].X, &P[i].Y)
		coords, l := pr.c.G2(Q[i])
		if l == nil {
			pr.commit(coords[:]...)
			l = pr.c.ComputeLines(Q[i])
		} else {
			// precomputed lines are usually constants, which commit skips,
			// but a circuit may take them from the witness
			for _, half := range l {
				for _, li := range half {
					if li != nil {
						pr.commit(li.R0[0], li.R0[1], li.R1[0], li.R1[1])
					}
				}
			}
		}
		lines[i] = l
	}
	return lines, nil
}

// millerLoopLines runs the loop over the lines. init seeds the accumulator
// and is multiplied back in on every positive digit, initInv on every
// negative one; both are nil for a plain Miller loop, and initInv may be nil
// when the loop counter has no negative digits.
func (pr *Pairing[F, G2El, GtEl]) millerLoopLines(P []*G1Affine[F], lines []*Lines[F], init, initInv *poly[F]) *polyring.PolyRingAccumulator[F] {
	n := len(P)
	fp := pr.fp

	// precomputations. A point at infinity has y = 0, whose inverse is
	// undefined, so yInv is forced to 0 there.
	yInv := make([]*emulated.Element[F], n)
	xNegOverY := make([]*emulated.Element[F], n)
	for k := range n {
		isYZero := fp.IsZero(&P[k].Y)
		y := fp.Select(isYZero, fp.One(), &P[k].Y)
		yInv[k] = fp.Select(isYZero, fp.Zero(), fp.Inverse(y))
		xNegOverY[k] = fp.Neg(fp.Mul(&P[k].X, yInv[k]))
	}

	// line k of iteration i, evaluated at P[k] as a sparse ring element
	oneAt, r0At, r1At := pr.c.LineSlots()
	size := max(oneAt, r0At+6, r1At+6) + 1
	line := func(k, half, i int) *poly[F] {
		l := lines[k][half][i]
		coeffs := make([]*emulated.Element[F], size)
		coeffs[oneAt] = fp.One()
		pr.embedE2(coeffs, r0At, fp.Mul(l.R0[0], xNegOverY[k]), fp.Mul(l.R0[1], xNegOverY[k]))
		pr.embedE2(coeffs, r1At, fp.Mul(l.R1[0], yInv[k]), fp.Mul(l.R1[1], yInv[k]))
		return &poly[F]{Coeffs: coeffs}
	}

	res := pr.accumulator(accumulatorTargetDegree)
	if init != nil {
		res.Mul(init)
	}

	loopCounter := pr.c.LoopCounter()
	for i := len(loopCounter) - 2; i >= 0; i-- {
		res.Sqr()

		switch loopCounter[i] {
		case 0:
			for k := range n {
				res.Mul(line(k, 0, i))
			}
		case 1, -1:
			if init != nil {
				// multiply by init on a positive digit, by its inverse on a negative one
				if loopCounter[i] == 1 {
					res.Mul(init)
				} else {
					res.Mul(initInv)
				}
			}
			for k := range n {
				res.Mul(line(k, 0, i)).Mul(line(k, 1, i))
			}
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}

		// collapse the iteration into a single ring check, so the accumulated
		// degree stays bounded whatever n is
		res.Eval()
	}

	if last := pr.c.LastLines(); last >= 0 {
		for k := range n {
			res.Mul(line(k, 0, last)).Mul(line(k, 1, last))
		}
	}
	return res
}
