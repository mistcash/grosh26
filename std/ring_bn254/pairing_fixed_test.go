package ring_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
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

// groth16Sim checks a four-pairing product with three pairs
// in the loop and the fourth folded in as a previous Miller loop value. Q2
// and Q3 are the same G2 point carrying precomputed lines, so their ladders
// and subgroup checks never enter the circuit.
type groth16Sim struct {
	P1, P2, P3 sw_bn254.G1Affine
	Q1, Q2, Q3 sw_bn254.G2Affine
	Prev       sw_bn254.GTEl
}

func (c *groth16Sim) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	pairing.AssertIsOnG1(&c.P1)
	pairing.AssertIsOnG1(&c.P2)
	pairing.AssertIsOnG1(&c.P3)
	return pairing.PairingCheck(
		[]*G1Affine{&c.P1, &c.P2, &c.P3},
		[]*G2Affine{&c.Q1, &c.Q2, &c.Q3},
		&c.Prev,
	)
}

func TestThreePairingFixedPrev(t *testing.T) {
	assert := test.NewAssert(t)
	// e(2p, q) * e(-pq, g2) * e(-2pq, g2) * e(p, q) == 1: the middle two
	// share one fixed G2 with precomputed lines, the last is folded in as
	// the previous Miller loop value instead of a pass through the loop.
	p, pqNeg, q, g2 := randomPairingTriple(t)
	var p1, p2, p3 bn254.G1Affine
	p1.Double(&p)
	p2.Set(&pqNeg)
	p3.Double(&pqNeg)

	fixed := sw_bn254.NewG2AffineFixed(g2)
	unassigned := &groth16Sim{Q2: fixed, Q3: fixed}
	assignment := &groth16Sim{
		P1:   sw_bn254.NewG1Affine(p1), // 2p
		Q1:   sw_bn254.NewG2Affine(q),  // q
		P2:   sw_bn254.NewG1Affine(p2), // -pq
		Q2:   fixed,                    // g2, lines precomputed
		P3:   sw_bn254.NewG1Affine(p3), // -2pq
		Q3:   fixed,                    // g2, lines precomputed
		Prev: sw_bn254.NewGTEl(previousMillerValue(t, p, q)),
	}
	err := test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
