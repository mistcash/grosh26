package ringpairing

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type bnFp = emparams.BN254Fp

// bn254Curve is BN254: 𝔽p¹² = 𝔽p[w]/(w¹² - 18w⁶ + 82), a D-type twist whose
// lines are 1 + c₃w + c₄w³, and a Miller loop over 6x₀+2 in signed binary
// closed by two extra lines through π(Q) and -π²(Q).
type bn254Curve struct {
	ladder[bnFp]
	e12 *fields_bn254.Ext12
	g   *sw_bn254.Pairing

	// Endomorphism constants, same values as gnark's G2 (sw_bn254/g2.go
	// NewG2): ψ scales the conjugated coordinates by psiX and psiY, φ = ψ²
	// scales x by the cube root of unity phiW.
	psiX, psiY *e2[bnFp]
	phiW       *emulated.Element[bnFp]
}

func newBN254Curve(api frontend.API) (*bn254Curve, error) {
	g, err := sw_bn254.NewPairing(api)
	if err != nil {
		return nil, err
	}
	fp, err := emulated.NewField[bnFp](api)
	if err != nil {
		return nil, err
	}
	l := ladder[bnFp]{ext2[bnFp]{api: api, fp: fp}}
	return &bn254Curve{
		ladder: l,
		e12:    fields_bn254.NewExt12(api),
		g:      g,
		psiX: l.newConst(
			"21575463638280843010398324269430826099269044274347216827212613867836435027261",
			"10307601595873709700152284273816112264069230130616436755625194854815875713954"),
		psiY: l.newConst(
			"2821565182194536844548159561693502659359617185244120367078079554186484126554",
			"3505843767911556378687030309984248845540243509899259641013678093033130930403"),
		phiW: fp.NewElement("21888242871839275220042445260109153167277707414472061641714758635765020556616"),
	}, nil
}

func (c *bn254Curve) xi0() int64                   { return 9 }
func (c *bn254Curve) loopCounter() []int8          { return bn254.LoopCounter[:] }
func (c *bn254Curve) lineSlots() (one, r0, r1 int) { return 0, 1, 3 }
func (c *bn254Curve) lastLines() int               { return len(bn254.LoopCounter) - 1 }
func (c *bn254Curve) conjugateMillerLoop() bool    { return false }
func (c *bn254Curve) needsResidue() bool           { return true }

func (c *bn254Curve) g2(Q *sw_bn254.G2Affine) (x, y *e2[bnFp], lines *lineEvals[bnFp]) {
	x = &e2[bnFp]{A0: Q.P.X.A0, A1: Q.P.X.A1}
	y = &e2[bnFp]{A0: Q.P.Y.A0, A1: Q.P.Y.A1}
	if Q.Lines == nil {
		return x, y, nil
	}
	lines = newLineEvals[bnFp](len(Q.Lines[0]))
	for half := range Q.Lines {
		for i, l := range Q.Lines[half] {
			if l != nil {
				lines[half][i] = &lineEval[bnFp]{
					R0: e2[bnFp]{A0: l.R0.A0, A1: l.R0.A1},
					R1: e2[bnFp]{A0: l.R1.A0, A1: l.R1.A1},
				}
			}
		}
	}
	return x, y, lines
}

// computeLines runs the [6x₀+2]Q ladder. Q is asserted to be on the twist
// first, with gnark's check; the prime-order subgroup check then reuses the
// ladder endpoint instead of a separate scalar multiplication, exactly like
// gnark's own computeLines: [6x₀+2]Q + ψ(Q) + ψ³(Q) == ψ²(Q), see Sec. 3.1.2
// (Remark 2) of https://eprint.iacr.org/2022/348.
func (c *bn254Curve) computeLines(Q *sw_bn254.G2Affine) *lineEvals[bnFp] {
	c.g.AssertIsOnTwist(Q)
	x, y, _ := c.g2(Q)
	q := &g2Point[bnFp]{X: *x, Y: *y}
	loopCounter := bn254.LoopCounter
	n := len(loopCounter)
	lines := newLineEvals[bnFp](n)

	acc, l := c.doubleStep(q)
	lines[0][n-2] = l
	lines[1][n-3] = c.lineCompute(acc, q)
	acc, lines[0][n-3] = c.addStep(acc, q)
	for i := n - 4; i >= 0; i-- {
		if loopCounter[i] == 0 {
			acc, lines[0][i] = c.doubleStep(acc)
		} else {
			acc, lines[0][i], lines[1][i] = c.doubleAndAddStep(acc, q, loopCounter[i] == -1)
		}
	}

	// Subgroup check on the ladder endpoint acc == [6x₀+2]Q. A full
	// AssertIsOnG2 here would redo an [x₀]Q scalar multiplication on top of
	// the ladder; the short-vector relation gets the same assurance from
	// the endpoint the ladder already computed.
	psiQ := c.psi(q)
	psi2Q := c.phi(q)
	lhs := c.addPoints(c.addPoints(acc, psiQ), c.psi(psi2Q))
	c.assertIsEqual(&lhs.X, &psi2Q.X)
	c.assertIsEqual(&lhs.Y, &psi2Q.Y)

	// the two extra lines, through π(Q) and -π²(Q): on the twist those are
	// exactly ψ(Q) and φ(Q), already at hand from the subgroup check
	acc, lines[0][n-1] = c.addStep(acc, psiQ)
	lines[1][n-1] = c.lineCompute(acc, psi2Q)
	return lines
}

// psi maps q through ψ: x ↦ psiX·x̄, y ↦ psiY·ȳ.
func (c *bn254Curve) psi(q *g2Point[bnFp]) *g2Point[bnFp] {
	return &g2Point[bnFp]{
		X: *c.mul(c.conjugate(&q.X), c.psiX),
		Y: *c.mul(c.conjugate(&q.Y), c.psiY),
	}
}

// phi maps q through φ = ψ²: x ↦ phiW·x, y ↦ -y.
func (c *bn254Curve) phi(q *g2Point[bnFp]) *g2Point[bnFp] {
	return &g2Point[bnFp]{X: *c.mulByElement(&q.X, c.phiW), Y: *c.neg(&q.Y)}
}

func (c *bn254Curve) assertIsOnG1(P *sw_bn254.G1Affine) { c.g.AssertIsOnG1(P) }
func (c *bn254Curve) assertIsOnG2(Q *sw_bn254.G2Affine) { c.g.AssertIsOnG2(Q) }

func (c *bn254Curve) toPoly(a *sw_bn254.GTEl) *poly[bnFp] {
	return &poly[bnFp]{Coeffs: []*emulated.Element[bnFp]{
		&a.A0, &a.A1, &a.A2, &a.A3, &a.A4, &a.A5, &a.A6, &a.A7, &a.A8, &a.A9, &a.A10, &a.A11,
	}}
}

func (c *bn254Curve) fromPoly(p *poly[bnFp]) *sw_bn254.GTEl {
	if len(p.Coeffs) != 12 {
		panic("ringpairing: expected 12 coefficients")
	}
	k := p.Coeffs
	return &sw_bn254.GTEl{
		A0: *k[0], A1: *k[1], A2: *k[2], A3: *k[3], A4: *k[4], A5: *k[5],
		A6: *k[6], A7: *k[7], A8: *k[8], A9: *k[9], A10: *k[10], A11: *k[11],
	}
}

func (c *bn254Curve) toTower(a *sw_bn254.GTEl) [12]*emulated.Element[bnFp] {
	return c.e12.ToTower(a)
}

func (c *bn254Curve) fromTower(a [12]*emulated.Element[bnFp]) *sw_bn254.GTEl {
	return c.e12.FromTower(a)
}

// checkHint: gnark's pairingCheckHint returns the inverse residue witness,
// millerLoopAndCheckFinalExpHint the witness itself.
func (c *bn254Curve) checkHint(withPrevious bool) (solver.Hint, bool) {
	if withPrevious {
		return bn254MillerLoopAndCheckHint, false
	}
	return bn254PairingCheckHint, true
}

// residueTail completes c^(-λ) with λ = 6x₀+2 + q³ - q² + q: the loop
// already contributed c^-(6x₀+2), and c^(-q²) is c^(q²) inverted.
func (c *bn254Curve) residueTail(res, resInv *sw_bn254.GTEl) []*sw_bn254.GTEl {
	return []*sw_bn254.GTEl{
		c.e12.FrobeniusCube(resInv),
		c.e12.FrobeniusSquare(res),
		c.e12.Frobenius(resInv),
	}
}

func (c *bn254Curve) mulGT(x, y *sw_bn254.GTEl) *sw_bn254.GTEl { return c.e12.Mul(x, y) }
func (c *bn254Curve) conjugateGT(x *sw_bn254.GTEl) *sw_bn254.GTEl {
	return c.e12.Conjugate(x)
}
func (c *bn254Curve) finalExponentiation(x *sw_bn254.GTEl) *sw_bn254.GTEl {
	return c.g.FinalExponentiation(x)
}
func (c *bn254Curve) assertIsEqualGT(x, y *sw_bn254.GTEl) { c.e12.AssertIsEqual(x, y) }
