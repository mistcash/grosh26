// Package ring_bls12381 is the BLS12-381 ring pairing: the curve-specific half
// of std/ringpairing for 𝔽p¹² = 𝔽p[w]/(w¹² - 2w⁶ + 2), an M-type twist whose
// lines are c₀ + c₁w² + w³, and a Miller loop over the negative seed x₀ in
// plain binary, its raw value conjugated.
//
// Points, the target group and the witness constructors are gnark's: build
// witness points with sw_bls12381.NewG1Affine / NewG2Affine and fixed points with
// sw_bls12381.NewG2AffineFixed, whose precomputed lines skip the ladder.
package ring_bls12381

import (
	"fmt"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/grosh26/std/ringpairing"
)

type (
	baseEl = emulated.Element[emulated.BLS12381Fp]
	curveF = emulated.Field[emulated.BLS12381Fp]

	G1Affine = sw_bls12381.G1Affine
	G2Affine = sw_bls12381.G2Affine
	GTEl     = sw_bls12381.GTEl

	// Pairing is the BLS12-381 ring pairing; see [ringpairing.Pairing].
	Pairing = ringpairing.Pairing[emulated.BLS12381Fp, G2Affine, GTEl]
)

// NewPairing returns a BLS12-381 ring pairing. Call it before anything else in the
// circuit creates an emulated field, see [ringpairing.New].
func NewPairing(api frontend.API) (*Pairing, error) {
	return ringpairing.New(api, func(api frontend.API) (ringpairing.Curve[emulated.BLS12381Fp, G2Affine, GTEl], error) {
		return newCurve(api)
	})
}

// The hints below are gnark's, and unexported. Their maths -- inverting an
// 𝔽p¹² element, and finding the residue witness of a pairing check, with or
// without a previous Miller loop value folded in -- is not something to keep
// a second copy of, so they are picked out of the exported hint lists by name
// instead. All are registered with the solver by gnark's own package init.
var (
	inverseE12Hint                 = gnarkHint(fields_bls12381.GetHints(), "inverseE12Hint")
	pairingCheckHint               = gnarkHint(sw_bls12381.GetHints(), "pairingCheckHint")
	millerLoopAndCheckFinalExpHint = gnarkHint(sw_bls12381.GetHints(), "millerLoopAndCheckFinalExpHint")
)

// gnarkHint returns the hint named name from hints. It panics when there is no
// such hint, which would mean gnark renamed or dropped it.
func gnarkHint(hints []solver.Hint, name string) solver.Hint {
	for _, h := range hints {
		if hintName := solver.GetHintName(h); strings.HasSuffix(hintName, "."+name) {
			return h
		}
	}
	panic(fmt.Sprintf("ring_bls12381: gnark no longer exposes a hint named %q", name))
}

// curve implements [ringpairing.Curve] for BLS12-381.
type curve struct {
	fp   *curveF
	ext2 *fields_bls12381.Ext2
	e12  *fields_bls12381.Ext12
	g    *sw_bls12381.Pairing
}

func newCurve(api frontend.API) (*curve, error) {
	g, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new gnark pairing: %w", err)
	}
	fp, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, err
	}
	return &curve{fp: fp, ext2: fields_bls12381.NewExt2(api), e12: fields_bls12381.NewExt12(api), g: g}, nil
}

func (c *curve) Xi0() int64                   { return 1 }
func (c *curve) LoopCounter() []int8          { return bls12381.LoopCounter[:] }
func (c *curve) LineSlots() (one, r0, r1 int) { return 3, 2, 0 }
func (c *curve) LastLines() int               { return -1 }
func (c *curve) ConjugateMillerLoop() bool    { return true }
func (c *curve) NeedsResidue() bool           { return false }
func (c *curve) InverseHint() solver.Hint     { return inverseE12Hint }

// CheckHint: both of gnark's hints return the inverse residue witness.
func (c *curve) CheckHint(withPrevious bool) (solver.Hint, bool) {
	if withPrevious {
		return millerLoopAndCheckFinalExpHint, true
	}
	return pairingCheckHint, true
}

// ResidueTail completes (c⁻¹)^λ with λ = q - x₀: the loop seeded with c⁻¹
// already contributed (c⁻¹)^(-x₀) -- its raw value is checked unconjugated,
// as in gnark -- leaving (c⁻¹)^q.
func (c *curve) ResidueTail(_, resInv *GTEl) []*GTEl {
	return []*GTEl{c.e12.Frobenius(resInv)}
}

func (c *curve) G2(Q *G2Affine) ([4]*baseEl, *ringpairing.Lines[emulated.BLS12381Fp]) {
	coords := [4]*baseEl{&Q.P.X.A0, &Q.P.X.A1, &Q.P.Y.A0, &Q.P.Y.A1}
	if Q.Lines == nil {
		return coords, nil
	}
	lines := ringpairing.NewLines[emulated.BLS12381Fp](len(Q.Lines[0]))
	for half := range Q.Lines {
		for i, l := range Q.Lines[half] {
			if l != nil {
				lines[half][i] = toLine(&l.R0, &l.R1)
			}
		}
	}
	return coords, lines
}

func toLine(r0, r1 *fields_bls12381.E2) *ringpairing.Line[emulated.BLS12381Fp] {
	return &ringpairing.Line[emulated.BLS12381Fp]{
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
