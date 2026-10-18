package ringpairing

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/grosh26/std/polyring"
)

// accumulatorTargetDegree caps the degree of a product queued in the ring
// accumulator before it is collapsed into one deferred check. A Miller loop
// iteration squares the running value (degree 22) and multiplies in line
// evaluations of degree 8 or 9, so 69 fits a squaring plus five lines.
const accumulatorTargetDegree = 69

// G1Affine is a point on the curve over the emulated base field F: gnark's
// sw_bn254.G1Affine or sw_bls12381.G1Affine.
type G1Affine[F emulated.FieldParams] = sw_emulated.AffinePoint[F]

// BN254 and BLS12381 are the ring pairings over the two supported curves, in
// gnark's own point and target group types. Build witness points with
// sw_*.NewG1Affine / NewG2Affine and fixed points with sw_*.NewG2AffineFixed:
// a Q carrying Lines skips the ladder.
type (
	BN254    = Pairing[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl]
	BLS12381 = Pairing[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl]
)

// curve is everything about a pairing-friendly curve the ring pairing needs
// beyond the ring itself: gnark's types, hints and 𝔽p¹² maps, the Miller loop's
// shape and the ladder computing lines for a G2 point given as a witness.
type curve[F emulated.FieldParams, G2El, GtEl any] interface {
	// xi0 is the real part of the sextic non-residue ξ = ξ₀ + u.
	xi0() int64
	// loopCounter is the Miller loop's signed binary expansion, most
	// significant digit last; the loop starts at the second-to-last digit.
	loopCounter() []int8
	// lineSlots are the powers of w a line 1 + (R0·(-x/y)) + (R1·(1/y))
	// evaluated at P = (x, y) puts its three terms on, the 𝔽p² ones embedded
	// with [ring.embedE2].
	lineSlots() (one, r0, r1 int)
	// lastLines is the iteration index of lines applied after the loop, or -1
	// for none (BN254 has two, through π(Q) and -π²(Q)).
	lastLines() int
	// conjugateMillerLoop reports whether the loop's raw value is conjugated
	// into the Miller loop value, as for BLS12-381's negative seed.
	conjugateMillerLoop() bool

	g2(Q *G2El) (x, y *e2[F], lines *lineEvals[F])
	// computeLines runs the ladder for a witness Q, asserting Q is on G2.
	computeLines(Q *G2El) *lineEvals[F]
	assertIsOnG1(P *G1Affine[F])
	assertIsOnG2(Q *G2El)

	toPoly(x *GtEl) *poly[F]
	fromPoly(x *poly[F]) *GtEl
	toTower(x *GtEl) [12]*emulated.Element[F]
	fromTower(x [12]*emulated.Element[F]) *GtEl

	// checkHint returns gnark's residue witness hint for a pairing check,
	// with or without a previous Miller loop value, and whether its first
	// output is the residue witness's inverse rather than the witness.
	checkHint(withPrevious bool) (hint solver.Hint, givesInverse bool)
	// residueTail returns the factors that turn the loop's output
	// f·c^(-x₀) into f·c^(-λ)·(scaling)⁻¹, given c and c⁻¹. c is nil when
	// [curve.needsResidue] is false.
	residueTail(c, cInv *GtEl) []*GtEl
	// needsResidue reports whether the check needs c itself, not just c⁻¹.
	needsResidue() bool

	// mulGT, conjugateGT and finalExponentiation are gnark's, coefficient-wise.
	mulGT(x, y *GtEl) *GtEl
	conjugateGT(x *GtEl) *GtEl
	finalExponentiation(x *GtEl) *GtEl
	assertIsEqualGT(x, y *GtEl)
}

// Pairing computes pairings with the 𝔽p¹² products evaluated in the
// polynomial ring. Point arithmetic, subgroup checks, the Frobenius maps and
// the residue witness hints all come from gnark; what is different is the
// Miller loop accumulation, which queues line evaluations as ring products
// instead of reducing each one with a sparse multiplication.
type Pairing[F emulated.FieldParams, G2El, GtEl any] struct {
	*ring[F]
	c curve[F, G2El, GtEl]
}

// NewBN254 returns a BN254 ring pairing, see [New].
func NewBN254(api frontend.API) (*BN254, error) {
	return New[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl](api)
}

// NewBLS12381 returns a BLS12-381 ring pairing, see [New].
func NewBLS12381(api frontend.API) (*BLS12381, error) {
	return New[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
}

// New returns the ring pairing over the curve G2El belongs to, sharing api's
// emulated field. It registers the ring checker, so call it before anything
// else in the circuit creates an emulated field; see [newRing].
func New[F emulated.FieldParams, G2El, GtEl any](api frontend.API) (*Pairing[F, G2El, GtEl], error) {
	var (
		r   *ring[F]
		c   any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		r = newRing[F](api, 9, bn254InverseHint)
		c, err = newBN254Curve(api)
	case *sw_bls12381.G2Affine:
		r = newRing[F](api, 1, bls12381InverseHint)
		c, err = newBLS12381Curve(api)
	default:
		return nil, fmt.Errorf("ringpairing: unsupported G2 type %T", (*G2El)(nil))
	}
	if err != nil {
		return nil, err
	}
	cc, ok := c.(curve[F, G2El, GtEl])
	if !ok {
		return nil, fmt.Errorf("ringpairing: base field or target group does not match G2 type %T", (*G2El)(nil))
	}
	return &Pairing[F, G2El, GtEl]{ring: r, c: cc}, nil
}

// AssertIsOnG1 asserts P is on the curve and in the prime-order subgroup.
func (pr *Pairing[F, G2El, GtEl]) AssertIsOnG1(P *G1Affine[F]) { pr.c.assertIsOnG1(P) }

// AssertIsOnG2 asserts Q is on the twist and in the prime-order subgroup.
func (pr *Pairing[F, G2El, GtEl]) AssertIsOnG2(Q *G2El) { pr.c.assertIsOnG2(Q) }

// AssertIsEqual asserts x == y in 𝔽p¹².
func (pr *Pairing[F, G2El, GtEl]) AssertIsEqual(x, y *GtEl) { pr.c.assertIsEqualGT(x, y) }

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
	res := pr.c.fromPoly(pr.millerLoopLines(P, lines, nil, nil).Eval())
	if pr.c.conjugateMillerLoop() {
		res = pr.c.conjugateGT(res)
	}
	return res, nil
}

// Pair computes the reduced pairing ∏ᵢ e(Pᵢ, Qᵢ).
func (pr *Pairing[F, G2El, GtEl]) Pair(P []*G1Affine[F], Q []*G2El) (*GtEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	return pr.c.finalExponentiation(res), nil
}

// PairingCheck asserts ∏ᵢ e(Pᵢ, Qᵢ) == 1 following Section 4 of
// [On Proving Pairings]: instead of a final exponentiation, the prover
// supplies a residue witness and the check folds it into the Miller loop.
//
// A Q with precomputed lines (sw_*.NewG2AffineFixed) skips the ladder and
// the subgroup check; the rest run them in-circuit. An optional previous
// Miller loop value is folded in as one factor instead of a pass through the
// loop (cf. gnark's MillerLoopAndMul), in the form gnark's
// AssertMultiMillerLoopAndFinalExpIsOne takes it: MillerLoopFixedQ output,
// conjugated for BLS12-381. The G1 points are not checked either way, see
// [Pairing.AssertIsOnG1].
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
		x, y, _ := pr.c.g2(Q[i])
		inputs = append(inputs, &x.A0, &x.A1, &y.A0, &y.A1)
	}
	if previous != nil {
		// the residue covers the whole product, so previous travels with
		// the points as its tower limbs.
		tower := pr.c.toTower(previous)
		inputs = append(inputs, tower[:]...)
	}
	checkHint, givesInverse := pr.c.checkHint(previous != nil)
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
	w := pr.c.toPoly(pr.c.fromTower([12]*emulated.Element[F](hint[:12])))
	switch {
	case !givesInverse:
		c, cInv = w, pr.inverse(w)
	case pr.c.needsResidue():
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
		cGT = pr.c.fromPoly(c)
	}
	for _, f := range pr.c.residueTail(cGT, pr.c.fromPoly(cInv)) {
		res.Mul(pr.c.toPoly(f))
	}

	prod := pr.c.fromPoly(res.Eval())
	if previous != nil {
		// A previous value is a plain factor: the loop's squarings would
		// otherwise raise it along with everything else. This uses gnark's
		// E12 arithmetic, not the ring: the ring reads raw limbs, which
		// ValueOf constants only gain on their first genuine field op.
		prod = pr.c.mulGT(prod, previous)
	}
	pr.assertIsOne(pr.c.toPoly(prod))
	return nil
}

// prepare validates the pairs, commits the points the ring products are
// built from and returns each Q's lines, running the ladder for those not
// carrying precomputed ones.
func (pr *Pairing[F, G2El, GtEl]) prepare(P []*G1Affine[F], Q []*G2El) ([]*lineEvals[F], error) {
	if len(P) == 0 || len(P) != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}
	lines := make([]*lineEvals[F], len(Q))
	for i := range P {
		if P[i] == nil || Q[i] == nil {
			return nil, fmt.Errorf("pair %d is nil", i)
		}
		pr.commit(&P[i].X, &P[i].Y)
		x, y, l := pr.c.g2(Q[i])
		if l == nil {
			pr.commit(&x.A0, &x.A1, &y.A0, &y.A1)
			l = pr.c.computeLines(Q[i])
		} else {
			// precomputed lines are usually constants, which commit skips,
			// but a circuit may take them from the witness
			for _, half := range l {
				for _, li := range half {
					if li != nil {
						pr.commit(&li.R0.A0, &li.R0.A1, &li.R1.A0, &li.R1.A1)
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
func (pr *Pairing[F, G2El, GtEl]) millerLoopLines(P []*G1Affine[F], lines []*lineEvals[F], init, initInv *poly[F]) *polyring.PolyRingAccumulator[F] {
	n := len(P)
	fp := pr.fp

	// precomputations. A point at infinity has y = 0, whose inverse is
	// undefined, so yInv is forced to 0 there.
	yInv := make([]*emulated.Element[F], n)
	xNegOverY := make([]*emulated.Element[F], n)
	for k := 0; k < n; k++ {
		isYZero := fp.IsZero(&P[k].Y)
		y := fp.Select(isYZero, fp.One(), &P[k].Y)
		yInv[k] = fp.Select(isYZero, fp.Zero(), fp.Inverse(y))
		xNegOverY[k] = fp.Neg(fp.Mul(&P[k].X, yInv[k]))
	}

	// line k of iteration i, evaluated at P[k] as a sparse ring element
	oneAt, r0At, r1At := pr.c.lineSlots()
	size := max(oneAt, r0At+6, r1At+6) + 1
	line := func(k, half, i int) *poly[F] {
		l := lines[k][half][i]
		coeffs := make([]*emulated.Element[F], size)
		coeffs[oneAt] = fp.One()
		pr.embedE2(coeffs, r0At, fp.Mul(&l.R0.A0, xNegOverY[k]), fp.Mul(&l.R0.A1, xNegOverY[k]))
		pr.embedE2(coeffs, r1At, fp.Mul(&l.R1.A0, yInv[k]), fp.Mul(&l.R1.A1, yInv[k]))
		return &poly[F]{Coeffs: coeffs}
	}

	res := pr.accumulator(accumulatorTargetDegree)
	if init != nil {
		res.Mul(init)
	}

	loopCounter := pr.c.loopCounter()
	for i := len(loopCounter) - 2; i >= 0; i-- {
		res.Sqr()

		switch loopCounter[i] {
		case 0:
			for k := 0; k < n; k++ {
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
			for k := 0; k < n; k++ {
				res.Mul(line(k, 0, i)).Mul(line(k, 1, i))
			}
		default:
			panic(fmt.Sprintf("invalid loop counter value %d", loopCounter[i]))
		}

		// collapse the iteration into a single ring check, so the accumulated
		// degree stays bounded whatever n is
		res.Eval()
	}

	if last := pr.c.lastLines(); last >= 0 {
		for k := 0; k < n; k++ {
			res.Mul(line(k, 0, last)).Mul(line(k, 1, last))
		}
	}
	return res
}
