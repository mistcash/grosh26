// Package ring_bn254 is the BN254 ring pairing: the curve-specific half of
// std/ringpairing for 𝔽p¹² = 𝔽p[w]/(w¹² - 18w⁶ + 82), a D-type twist whose
// lines are 1 + c₃w + c₄w³, and a Miller loop over 6x₀+2 in signed binary
// closed by two extra lines through π(Q) and -π²(Q).
//
// Points, the target group and the witness constructors are gnark's: build
// witness points with sw_bn254.NewG1Affine / NewG2Affine and fixed points with
// sw_bn254.NewG2AffineFixed, whose precomputed lines skip the ladder.
package ring_bn254

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/ringpairing"
)

type (
	baseEl = emulated.Element[emulated.BN254Fp]
	curveF = emulated.Field[emulated.BN254Fp]

	G1Affine = sw_bn254.G1Affine
	G2Affine = sw_bn254.G2Affine
	GTEl     = sw_bn254.GTEl

	// Pairing is the BN254 ring pairing; see [ringpairing.Pairing].
	Pairing = ringpairing.Pairing[emulated.BN254Fp, G2Affine, GTEl]
)

// NewPairing returns a BN254 ring pairing. Call it before anything else in the
// circuit creates an emulated field, see [ringpairing.New].
func NewPairing(api frontend.API) (*Pairing, error) {
	return ringpairing.New(api, func(api frontend.API) (ringpairing.Curve[emulated.BN254Fp, G2Affine, GTEl], error) {
		return newCurve(api)
	})
}

// curve implements [ringpairing.Curve] for BN254.
type curve struct {
	fp   *curveF
	ext2 *fields_bn254.Ext2
	e12  *fields_bn254.Ext12
	g    *sw_bn254.Pairing
}

func newCurve(api frontend.API) (*curve, error) {
	g, err := sw_bn254.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new gnark pairing: %w", err)
	}
	fp, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return nil, err
	}
	return &curve{fp: fp, ext2: fields_bn254.NewExt2(api), e12: fields_bn254.NewExt12(api), g: g}, nil
}

func (c *curve) Xi0() int64                   { return 9 }
func (c *curve) LoopCounter() []int8          { return bn254.LoopCounter[:] }
func (c *curve) LineSlots() (one, r0, r1 int) { return 0, 1, 3 }
func (c *curve) LastLines() int               { return len(bn254.LoopCounter) - 1 }
func (c *curve) ConjugateMillerLoop() bool    { return false }
func (c *curve) NeedsResidue() bool           { return true }
func (c *curve) InverseHint() solver.Hint     { return inverseE12Hint }

// CheckHint: gnark's pairingCheckHint returns the inverse residue witness,
// millerLoopAndCheckFinalExpHint the witness itself.
func (c *curve) CheckHint(withPrevious bool) (solver.Hint, bool) {
	if withPrevious {
		return millerLoopAndCheckFinalExpHint, false
	}
	return pairingCheckHint, true
}

// ResidueTail completes c^(-λ) with λ = 6x₀+2 + q³ - q² + q: the loop
// already contributed c^-(6x₀+2), and c^(-q²) is c^(q²) inverted.
func (c *curve) ResidueTail(res, resInv *GTEl) []*GTEl {
	return []*GTEl{c.e12.FrobeniusCube(resInv), c.e12.FrobeniusSquare(res), c.e12.Frobenius(resInv)}
}

func (c *curve) G2(Q *G2Affine) ([4]*baseEl, *ringpairing.Lines[emulated.BN254Fp]) {
	coords := [4]*baseEl{&Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1}
	if Q.Lines == nil {
		return coords, nil
	}
	lines := ringpairing.NewLines[emulated.BN254Fp](len(Q.Lines[0]))
	for half := range Q.Lines {
		for i, l := range Q.Lines[half] {
			if l != nil {
				lines[half][i] = toLine(&l.R0, &l.R1)
			}
		}
	}
	return coords, lines
}

func toLine(r0, r1 *fields_bn254.E2) *ringpairing.Line[emulated.BN254Fp] {
	return &ringpairing.Line[emulated.BN254Fp]{
		R0: [2]*baseEl{&r0.A0, &r0.A1},
		R1: [2]*baseEl{&r1.A0, &r1.A1},
	}
}

func (c *curve) AssertIsOnG1(P *G1Affine) { c.g.AssertIsOnG1(P) }
func (c *curve) AssertIsOnG2(Q *G2Affine) { c.g.AssertIsOnG2(Q) }

func (c *curve) Coeffs(a *GTEl) [12]*baseEl {
	return [12]*baseEl{&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5, &a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11}
}

func (c *curve) FromCoeffs(k [12]*baseEl) *GTEl {
	return &GTEl{
		A0: *k[0], A1: *k[1], A2: *k[2], A3: *k[3], A4: *k[4], A5: *k[5],
		A6: *k[6], A7: *k[7], A8: *k[8], A9: *k[9], A10: *k[10], A11: *k[11],
	}
}

func (c *curve) ToTower(a *GTEl) [12]*baseEl       { return c.e12.ToTower(a) }
func (c *curve) FromTower(a [12]*baseEl) *GTEl     { return c.e12.FromTower(a) }
func (c *curve) Mul(x, y *GTEl) *GTEl              { return c.e12.Mul(x, y) }
func (c *curve) Conjugate(x *GTEl) *GTEl           { return c.e12.Conjugate(x) }
func (c *curve) FinalExponentiation(x *GTEl) *GTEl { return c.g.FinalExponentiation(x) }
func (c *curve) AssertIsEqual(x, y *GTEl)          { c.e12.AssertIsEqual(x, y) }
