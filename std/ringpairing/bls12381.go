package ringpairing

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type blsFp = emparams.BLS12381Fp

// bls12381Curve is BLS12-381: 𝔽p¹² = 𝔽p[w]/(w¹² - 2w⁶ + 2), an M-type twist
// whose lines are c₀ + c₁w² + w³, and a Miller loop over the negative seed
// x₀ in plain binary, its raw value conjugated.
type bls12381Curve struct {
	ladder[blsFp]
	e12 *fields_bls12381.Ext12
	g   *sw_bls12381.Pairing

	// ψ constants, same values as gnark's G2 (sw_bls12381/g2.go NewG2):
	// x ↦ psiX·(x.A1 + x.A0·u), y ↦ psiY·ȳ.
	psiX *emulated.Element[blsFp]
	psiY *e2[blsFp]
}

func newBLS12381Curve(api frontend.API) (*bls12381Curve, error) {
	g, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return nil, err
	}
	fp, err := emulated.NewField[blsFp](api)
	if err != nil {
		return nil, err
	}
	l := ladder[blsFp]{ext2[blsFp]{api: api, fp: fp}}
	return &bls12381Curve{
		ladder: l,
		e12:    fields_bls12381.NewExt12(api),
		g:      g,
		psiX:   fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437"),
		psiY: l.newConst(
			"2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530",
			"1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"),
	}, nil
}

func (c *bls12381Curve) xi0() int64                   { return 1 }
func (c *bls12381Curve) loopCounter() []int8          { return bls12381.LoopCounter[:] }
func (c *bls12381Curve) lineSlots() (one, r0, r1 int) { return 3, 2, 0 }
func (c *bls12381Curve) lastLines() int               { return -1 }
func (c *bls12381Curve) conjugateMillerLoop() bool    { return true }
func (c *bls12381Curve) needsResidue() bool           { return false }

func (c *bls12381Curve) g2(Q *sw_bls12381.G2Affine) (x, y *e2[blsFp], lines *lineEvals[blsFp]) {
	x = &e2[blsFp]{A0: Q.P.X.A0, A1: Q.P.X.A1}
	y = &e2[blsFp]{A0: Q.P.Y.A0, A1: Q.P.Y.A1}
	if Q.Lines == nil {
		return x, y, nil
	}
	lines = newLineEvals[blsFp](len(Q.Lines[0]))
	for half := range Q.Lines {
		for i, l := range Q.Lines[half] {
			if l != nil {
				lines[half][i] = &lineEval[blsFp]{
					R0: e2[blsFp]{A0: l.R0.A0, A1: l.R0.A1},
					R1: e2[blsFp]{A0: l.R1.A0, A1: l.R1.A1},
				}
			}
		}
	}
	return x, y, lines
}

// computeLines runs the [|x₀|]Q ladder, opening with a tripling for the two
// leading ones of the seed. Q is asserted to be on the twist first, with
// gnark's check; the prime-order subgroup check ψ(Q) == [x₀]Q then reuses the
// ladder endpoint, exactly like gnark's own computeLines.
func (c *bls12381Curve) computeLines(Q *sw_bls12381.G2Affine) *lineEvals[blsFp] {
	c.g.AssertIsOnTwist(Q)
	x, y, _ := c.g2(Q)
	q := &g2Point[blsFp]{X: *x, Y: *y}
	loopCounter := bls12381.LoopCounter
	n := len(loopCounter)
	lines := newLineEvals[blsFp](n - 1)

	var acc *g2Point[blsFp]
	acc, lines[0][n-2], lines[1][n-2] = c.tripleStep(q)
	for i := n - 3; i >= 0; i-- {
		if loopCounter[i] == 0 {
			acc, lines[0][i] = c.doubleStep(acc)
		} else {
			acc, lines[0][i], lines[1][i] = c.doubleAndAddStep(acc, q, false)
		}
	}

	// acc == [|x₀|]Q and x₀ < 0, so ψ(Q) == [x₀]Q is ψ(Q) == -acc
	psiQ := c.psi(q)
	c.assertIsEqual(&acc.X, &psiQ.X)
	c.assertIsEqual(c.neg(&acc.Y), &psiQ.Y)
	return lines
}

// psi maps q through ψ: x ↦ psiX·(x.A1 + x.A0·u), y ↦ psiY·ȳ.
func (c *bls12381Curve) psi(q *g2Point[blsFp]) *g2Point[blsFp] {
	x := c.mulByElement(&q.X, c.psiX)
	return &g2Point[blsFp]{
		X: e2[blsFp]{A0: x.A1, A1: x.A0},
		Y: *c.mul(c.conjugate(&q.Y), c.psiY),
	}
}

func (c *bls12381Curve) assertIsOnG1(P *sw_bls12381.G1Affine) { c.g.AssertIsOnG1(P) }
func (c *bls12381Curve) assertIsOnG2(Q *sw_bls12381.G2Affine) { c.g.AssertIsOnG2(Q) }

func (c *bls12381Curve) toPoly(a *sw_bls12381.GTEl) *poly[blsFp] {
	return &poly[blsFp]{Coeffs: []*emulated.Element[blsFp]{
		&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5, &a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11,
	}}
}

func (c *bls12381Curve) fromPoly(p *poly[blsFp]) *sw_bls12381.GTEl {
	if len(p.Coeffs) != 12 {
		panic("ringpairing: expected 12 coefficients")
	}
	k := p.Coeffs
	return &sw_bls12381.GTEl{
		A0: *k[0], A1: *k[1], A2: *k[2], A3: *k[3], A4: *k[4], A5: *k[5],
		A6: *k[6], A7: *k[7], A8: *k[8], A9: *k[9], A10: *k[10], A11: *k[11],
	}
}

func (c *bls12381Curve) toTower(a *sw_bls12381.GTEl) [12]*emulated.Element[blsFp] {
	return c.e12.ToTower(a)
}

func (c *bls12381Curve) fromTower(a [12]*emulated.Element[blsFp]) *sw_bls12381.GTEl {
	return c.e12.FromTower(a)
}

// checkHint: both of gnark's hints return the inverse residue witness.
func (c *bls12381Curve) checkHint(withPrevious bool) (solver.Hint, bool) {
	if withPrevious {
		return bls12381MillerLoopAndCheckHint, true
	}
	return bls12381PairingCheckHint, true
}

// residueTail completes (c⁻¹)^λ with λ = q - x₀: the loop seeded with c⁻¹
// already contributed (c⁻¹)^(-x₀) -- its raw value is checked unconjugated,
// as in gnark -- leaving (c⁻¹)^q.
func (c *bls12381Curve) residueTail(_, resInv *sw_bls12381.GTEl) []*sw_bls12381.GTEl {
	return []*sw_bls12381.GTEl{c.e12.Frobenius(resInv)}
}

func (c *bls12381Curve) mulGT(x, y *sw_bls12381.GTEl) *sw_bls12381.GTEl { return c.e12.Mul(x, y) }
func (c *bls12381Curve) conjugateGT(x *sw_bls12381.GTEl) *sw_bls12381.GTEl {
	return c.e12.Conjugate(x)
}
func (c *bls12381Curve) finalExponentiation(x *sw_bls12381.GTEl) *sw_bls12381.GTEl {
	return c.g.FinalExponentiation(x)
}
func (c *bls12381Curve) assertIsEqualGT(x, y *sw_bls12381.GTEl) { c.e12.AssertIsEqual(x, y) }
