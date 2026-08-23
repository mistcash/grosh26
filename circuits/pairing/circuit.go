// Package pairing holds the demonstration circuit: a BN254 pairing check whose
// 𝔽p¹² arithmetic runs in the polynomial ring.
package pairing

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"

	"github.com/mistcash/grosh26/std/ring_bn254"
)

// Circuit proves knowledge of two G2 points Q1, Q2 for which
//
//	e(P1, Q1) · e(P2, Q2) == 1
//
// with P1 and P2 public. The pairing check is the one in [ring_bn254]: every
// 𝔽p¹² product of the Miller loop, and of the residue witness tail that stands
// in for the final exponentiation, is a deferred polynomial ring check.
//
// The public part is P1 and P2, two coordinates each, four limbs per
// coordinate, so the generated verifier takes 16 public inputs.
type Circuit struct {
	P1, P2 sw_bn254.G1Affine `gnark:",public"`
	Q1, Q2 sw_bn254.G2Affine `gnark:",secret"`
}

func (c *Circuit) Define(api frontend.API) error {
	pr, err := ring_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	pr.AssertIsOnG1(&c.P2)
	return pr.PairingCheck(
		[]*sw_bn254.G1Affine{&c.P1, &c.P2},
		[]*sw_bn254.G2Affine{&c.Q1, &c.Q2},
	)
}

// Assign builds a witness for the given scalars: P1 = [a]G1, Q1 = [b]G2,
// P2 = [-ab]G1 and Q2 = G2, which satisfy the check because the two pairings
// are e(G1,G2)^{ab} and e(G1,G2)^{-ab}.
func Assign(a, b *fr.Element) *Circuit {
	_, _, g1, g2 := bn254.Generators()

	var negAB fr.Element
	negAB.Mul(a, b).Neg(&negAB)

	var aBig, bBig, negABBig big.Int
	a.BigInt(&aBig)
	b.BigInt(&bBig)
	negAB.BigInt(&negABBig)

	var p1, p2 bn254.G1Affine
	var q1 bn254.G2Affine
	p1.ScalarMultiplication(&g1, &aBig)
	q1.ScalarMultiplication(&g2, &bBig)
	p2.ScalarMultiplication(&g1, &negABBig)

	return &Circuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(g2),
	}
}

// AssignRandom builds a witness for random scalars.
func AssignRandom() (*Circuit, error) {
	var a, b fr.Element
	if _, err := a.SetRandom(); err != nil {
		return nil, fmt.Errorf("random scalar: %w", err)
	}
	if _, err := b.SetRandom(); err != nil {
		return nil, fmt.Errorf("random scalar: %w", err)
	}
	return Assign(&a, &b), nil
}
