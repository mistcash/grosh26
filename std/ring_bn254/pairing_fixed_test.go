package ring_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type ThreePairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In3G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
	In3G2 G2Affine
}

func (c *ThreePairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	return pairing.PairingCheck(
		[]*G1Affine{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*G2Affine{&c.In1G2, &c.In2G2, &c.In3G2},
		nil,
	)
}

func TestThreePairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(2a, 2b) * e(-2a, b) * e(a, -2b) == 1
	p, pqNeg, q, g2 := randomPairingTriple(t)
	var p1, p2, p3 bn254.G1Affine
	var q1, q2, q3 bn254.G2Affine

	p1.Set(&p)
	q1.Set(&q)

	p2.Double(&p)
	q2.Double(&q)

	p3.Set(&pqNeg)
	q3.Set(&g2)
	q3.Double(&q3).Double(&q3)

	witness := ThreePairingCheckCircuit{
		In1G1: sw_bn254.NewG1Affine(p2), // 2p
		In1G2: sw_bn254.NewG2Affine(q),  // q
		In2G1: sw_bn254.NewG1Affine(p1), // p
		In2G2: sw_bn254.NewG2Affine(q2), // 2q
		In3G1: sw_bn254.NewG1Affine(p3), // -pq
		In3G2: sw_bn254.NewG2Affine(q3), // 4
	}
	err := test.IsSolved(&ThreePairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// scalarSplit draws a random scalar s and returns b = f - s·a, so the
// circuit can recombine f in-circuit as s·a + b.
func scalarSplit(t testing.TB, a, f bn254.G1Affine) (b bn254.G1Affine, s fr.Element) {
	t.Helper()
	if _, err := s.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var sBig big.Int
	s.BigInt(&sBig)
	var sA bn254.G1Affine
	sA.ScalarMultiplication(&a, &sBig)
	b.Sub(&f, &sA)
	return b, s
}

// groth16Sim checks a four-pairing product with three pairs
// in the loop and the fourth folded in as a previous Miller loop value. Q2
// and Q3 are the same G2 point carrying precomputed lines, so their ladders
// and subgroup checks never enter the circuit. The second pair's G1 point is
// recombined in-circuit as s·A + B from two witness points and a scalar.
type groth16Sim struct {
	P1, P3     sw_bn254.G1Affine
	A, B       sw_bn254.G1Affine `gnark:"-"`
	S          sw_bn254.Scalar
	Q1, Q2, Q3 sw_bn254.G2Affine
	Prev       sw_bn254.GTEl
}

func (c *groth16Sim) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	pairing.AssertIsOnG1(&c.P1)
	pairing.AssertIsOnG1(&c.P3)
	pairing.AssertIsOnG1(&c.A)
	pairing.AssertIsOnG1(&c.B)
	combined := curve.AddUnified(curve.ScalarMul(&c.A, &c.S), &c.B)
	return pairing.PairingCheck(
		[]*G1Affine{&c.P1, combined, &c.P3},
		[]*G2Affine{&c.Q1, &c.Q2, &c.Q3},
		&c.Prev,
	)
}

func TestGroth16Sim(t *testing.T) {
	assert := test.NewAssert(t)
	// e(2p, q) * e(s·A + B, g2) * e(-2pq, g2) * e(p, q) == 1 with s·A + B ==
	// -pq recombined in-circuit: the middle two share one fixed G2 with
	// precomputed lines, the last is folded in as the previous Miller loop
	// value instead of a pass through the loop.
	p, pqNeg, q, g2 := randomPairingTriple(t)
	var p1, p3 bn254.G1Affine
	p1.Double(&p)
	p3.Double(&pqNeg)

	bPt, sNative := scalarSplit(t, p, pqNeg)

	fixed := sw_bn254.NewG2AffineFixed(g2)
	unassigned := &groth16Sim{Q2: fixed, Q3: fixed, A: sw_bn254.NewG1Affine(p), B: sw_bn254.NewG1Affine(bPt)}

	assignment := &groth16Sim{
		P1:   sw_bn254.NewG1Affine(p1), // 2p
		Q1:   sw_bn254.NewG2Affine(q),  // q
		A:    sw_bn254.NewG1Affine(p),  // A, s·A + B == -pq
		S:    sw_bn254.NewScalar(sNative),
		B:    sw_bn254.NewG1Affine(bPt),
		Q2:   fixed,                    // g2, lines precomputed
		P3:   sw_bn254.NewG1Affine(p3), // -2pq
		Q3:   fixed,                    // g2, lines precomputed
		Prev: sw_bn254.NewGTEl(previousMillerValue(t, p, q)),
	}
	err := test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
