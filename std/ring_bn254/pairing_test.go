package ring_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
)

// randomPairingTriple returns [a]G1, [b]G2 and [-ab]G1, so that
// e([a]G1, [b]G2) · e([-ab]G1, G2) == 1.
func randomPairingTriple(t *testing.T) (p1, p2 bn254.G1Affine, q1, q2 bn254.G2Affine) {
	t.Helper()
	_, _, g1, g2 := bn254.Generators()

	var a, b fr.Element
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var negAB fr.Element
	negAB.Mul(&a, &b).Neg(&negAB)

	var aBig, bBig, negABBig big.Int
	a.BigInt(&aBig)
	b.BigInt(&bBig)
	negAB.BigInt(&negABBig)

	p1.ScalarMultiplication(&g1, &aBig)
	q1.ScalarMultiplication(&g2, &bBig)
	p2.ScalarMultiplication(&g1, &negABBig)
	q2 = g2
	return
}

type pairingCheckCircuit struct {
	P1, P2 sw_bn254.G1Affine
	Q1, Q2 sw_bn254.G2Affine
}

func (c *pairingCheckCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	pr.AssertIsOnG1(&c.P2)
	return pr.PairingCheck([]*G1Affine{&c.P1, &c.P2}, []*G2Affine{&c.Q1, &c.Q2})
}

func TestPairingCheck(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	assert.NoError(test.IsSolved(&pairingCheckCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckRejectsNonPairing makes sure the check is not vacuous.
func TestPairingCheckRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, q2 := randomPairingTriple(t)

	// p2 is now unrelated to p1, so the product of the two pairings is not one
	var p2 bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	p2.ScalarMultiplication(&g1, big.NewInt(42))

	assignment := &pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	assert.Error(test.IsSolved(&pairingCheckCircuit{}, assignment, ecc.BN254.ScalarField()))
}

type pairCircuit struct {
	P sw_bn254.G1Affine
	Q sw_bn254.G2Affine
	R sw_bn254.GTEl
}

func (c *pairCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pr.Pair([]*G1Affine{&c.P}, []*G2Affine{&c.Q})
	if err != nil {
		return err
	}
	pr.AssertIsEqual(res, &c.R)
	return nil
}

// TestPair pins the ring Miller loop against gnark-crypto's pairing.
func TestPair(t *testing.T) {
	assert := test.NewAssert(t)
	p, _, q, _ := randomPairingTriple(t)

	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)

	assignment := &pairCircuit{
		P: sw_bn254.NewG1Affine(p),
		Q: sw_bn254.NewG2Affine(q),
		R: sw_bn254.NewGTEl(res),
	}
	assert.NoError(test.IsSolved(&pairCircuit{}, assignment, ecc.BN254.ScalarField()))
}
