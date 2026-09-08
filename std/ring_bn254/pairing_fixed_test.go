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
