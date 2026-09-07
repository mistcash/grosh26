package ring_bn254

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fpbn "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
)

// Pair is one factor e(P, Q) of a [Pairing.PairingCheckPairs] product. How
// much of it is known when the circuit is built decides what the Miller loop
// has to do for it:
//
//   - [NewPair]: both points come from the witness. The loop runs the
//     [6x₀+2]Q ladder in-circuit and checks Q is in the prime-order subgroup.
//   - [Pairing.NewFixedQPair]: Q is fixed, P is not. Q's line evaluations are
//     precomputed off-circuit and enter the loop as constants, so both the
//     ladder and the subgroup check disappear from the circuit.
//   - [Pairing.NewFixedPair]: both points are fixed, so the pair's whole
//     Miller loop value is a constant and it never enters the loop at all.
//
// The zero value is not a usable pair; build one with a constructor.
type Pair struct {
	// p and q are the points as in-circuit elements -- witness variables or
	// constants. Both are needed whatever the pair's shape: the residue
	// witness hint is drawn from every point in the product.
	p *G1Affine
	q *G2Affine

	// lines holds Q's line evaluations when they are constants, and is nil
	// when Q comes from the witness and the loop has to compute them.
	lines *lineEvaluations

	// millerLoop is the pair's constant Miller loop value, set only when both
	// points are fixed. Such a pair contributes this one factor to the
	// product instead of a pass through the loop.
	millerLoop *basePoly
}

// NewPair returns the pair e(P, Q) with both points taken from the witness.
func NewPair(P *G1Affine, Q *G2Affine) Pair {
	return Pair{p: P, q: Q}
}

// NewFixedQPair returns the pair e(P, Q) for a Q fixed when the circuit is
// built: its line evaluations are computed here, off-circuit, and baked in as
// constants.
//
// That removes the in-circuit subgroup check along with the ladder, so Q is
// checked here instead -- a point off the twist, outside the prime-order
// subgroup, or at infinity is rejected with an error rather than by a
// constraint.
func (pr *Pairing) NewFixedQPair(P *G1Affine, Q bn254.G2Affine) (Pair, error) {
	if err := checkFixedG2(Q); err != nil {
		return Pair{}, err
	}
	lines := pr.precomputeLines(Q)
	q := pr.ConstG2(Q)
	return Pair{p: P, q: &q, lines: &lines}, nil
}

// NewFixedPair returns the pair e(P, Q) with both points fixed when the
// circuit is built -- e(α, β) in a Groth16 verifier, say. Its Miller loop
// value is computed here and folded into the product as a single constant
// factor, so the pair costs one multiplication in the ring rather than a pass
// through the loop.
//
// As in [Pairing.NewFixedQPair], both points are checked here rather than
// in-circuit.
func (pr *Pairing) NewFixedPair(P bn254.G1Affine, Q bn254.G2Affine) (Pair, error) {
	if P.IsInfinity() {
		return Pair{}, errors.New("fixed G1 point is the point at infinity")
	}
	if !P.IsInSubGroup() {
		return Pair{}, errors.New("fixed G1 point is not on the curve")
	}
	if err := checkFixedG2(Q); err != nil {
		return Pair{}, err
	}
	// MillerLoopFixedQ, not MillerLoop: the two disagree on the raw value.
	// gnark-crypto's projective loop carries the lines' Z factors, which the
	// final exponentiation kills but this check does not -- it compares raw
	// Miller loop values against the residue witness. The affine line form
	// MillerLoopFixedQ evaluates is the one the in-circuit loop uses, and the
	// one pairingCheckHint draws the residue witness from.
	ml, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{P},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(Q)},
	)
	if err != nil {
		return Pair{}, fmt.Errorf("miller loop: %w", err)
	}
	p, q := pr.ConstG1(P), pr.ConstG2(Q)
	return Pair{p: &p, q: &q, millerLoop: pr.ToPoly(pr.constE12(&ml))}, nil
}

// checkFixedG2 reports what makes Q unusable as a fixed pairing argument. The
// prime-order subgroup test covers the twist equation too, but not infinity:
// its lines are not defined, and the term it contributes is the empty
// product, which is not what a caller baking a point in means.
func checkFixedG2(Q bn254.G2Affine) error {
	if Q.IsInfinity() {
		return errors.New("fixed G2 point is the point at infinity")
	}
	if !Q.IsInSubGroup() {
		return errors.New("fixed G2 point is not in the prime-order subgroup")
	}
	return nil
}

// precomputeLines converts gnark-crypto's off-circuit line evaluations for a
// fixed Q into circuit constants. The layout it fills is the one
// [Pairing.millerLoopLines] consumes, the same one [Pairing.computeLines]
// produces in-circuit.
func (pr *Pairing) precomputeLines(Q bn254.G2Affine) lineEvaluations {
	native := bn254.PrecomputeLines(Q)
	var lines lineEvaluations
	for half := range native {
		for i := range native[half] {
			lines[half][i] = &lineEvaluation{
				R0: pr.constE2(&native[half][i].R0),
				R1: pr.constE2(&native[half][i].R1),
			}
		}
	}
	return lines
}

// ConstG1 builds p as an in-circuit constant: real limbs, allocated now,
// rather than a witness value resolved later.
func (pr *Pairing) ConstG1(p bn254.G1Affine) G1Affine {
	return G1Affine{X: *pr.constFp(&p.X), Y: *pr.constFp(&p.Y)}
}

// ConstG2 builds q as an in-circuit constant; see [Pairing.ConstG1].
func (pr *Pairing) ConstG2(q bn254.G2Affine) G2Affine {
	var g G2Affine
	g.P.X = pr.constE2(&q.X)
	g.P.Y = pr.constE2(&q.Y)
	return g
}

// constFp builds a base field element as an in-circuit constant.
func (pr *Pairing) constFp(v *fpbn.Element) *baseEl {
	b := new(big.Int)
	v.BigInt(b)
	return pr.fp.NewElement(b)
}

// constE2 builds an 𝔽p² element as an in-circuit constant.
func (pr *Pairing) constE2(v *bn254.E2) fields_bn254.E2 {
	return fields_bn254.E2{A0: *pr.constFp(&v.A0), A1: *pr.constFp(&v.A1)}
}

// constE12 converts a tower-representation 𝔽p¹² element into the direct
// extension gnark's [E12] uses, as in-circuit constants.
//
// The permutation is [fields_bn254.FromE12]'s, redone here only so the
// coefficients come out of NewElement with real limbs instead of witness
// values resolved later.
func (pr *Pairing) constE12(v *bn254.GT) *E12 {
	// aᵢⱼ₀ ↦ A₀..A₅ (less nine times its partner) and aᵢⱼ₁ ↦ A₆..A₁₁
	lo := [6]fpbn.Element{v.C0.B0.A0, v.C1.B0.A0, v.C0.B1.A0, v.C1.B1.A0, v.C0.B2.A0, v.C1.B2.A0}
	hi := [6]fpbn.Element{v.C0.B0.A1, v.C1.B0.A1, v.C0.B1.A1, v.C1.B1.A1, v.C0.B2.A1, v.C1.B2.A1}

	var c [12]*baseEl
	for i := range lo {
		var t fpbn.Element
		t.SetUint64(9)
		t.Mul(&t, &hi[i])
		t.Sub(&lo[i], &t)
		c[i] = pr.constFp(&t)
		c[6+i] = pr.constFp(&hi[i])
	}

	return &E12{
		A0: *c[0], A1: *c[1], A2: *c[2], A3: *c[3], A4: *c[4], A5: *c[5],
		A6: *c[6], A7: *c[7], A8: *c[8], A9: *c[9], A10: *c[10], A11: *c[11],
	}
}
