// Package poseidon holds the inner circuit for grosh26's recursion demo: a
// proof of knowledge of a poseidon 2→1 compression preimage.
package poseidon

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativeposeidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Circuit proves knowledge of A, B for which Digest = Compress(A, B), the
// poseidon2 2→1 compression function: one width-2 permutation, feed-forward.
// It carries no commitments of its own; the outer circuit that verifies its
// proof draws the three BSB22 commitments.
type Circuit struct {
	A, B   frontend.Variable `gnark:",secret"`
	Digest frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	perm, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return fmt.Errorf("new poseidon2 permutation: %w", err)
	}
	api.AssertIsEqual(perm.Compress(c.A, c.B), c.Digest)
	return nil
}

// Compress computes the poseidon2 2→1 compression of a and b natively, using
// the same width-2 default parameters the circuit's permutation uses.
func Compress(a, b *fr.Element) (*fr.Element, error) {
	perm := nativeposeidon2.NewDefaultPermutation()
	aBytes, bBytes := a.Bytes(), b.Bytes()
	digestBytes, err := perm.Compress(aBytes[:], bBytes[:])
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}
	var digest fr.Element
	if err := digest.SetBytesCanonical(digestBytes); err != nil {
		return nil, fmt.Errorf("decode digest: %w", err)
	}
	return &digest, nil
}

// Assign builds a witness for the given preimage.
func Assign(a, b *fr.Element) (*Circuit, error) {
	digest, err := Compress(a, b)
	if err != nil {
		return nil, err
	}
	var aBig, bBig, digestBig big.Int
	a.BigInt(&aBig)
	b.BigInt(&bBig)
	digest.BigInt(&digestBig)
	return &Circuit{A: &aBig, B: &bBig, Digest: &digestBig}, nil
}

// AssignRandom builds a witness for a random preimage.
func AssignRandom() (*Circuit, error) {
	var a, b fr.Element
	if _, err := a.SetRandom(); err != nil {
		return nil, fmt.Errorf("random preimage a: %w", err)
	}
	if _, err := b.SetRandom(); err != nil {
		return nil, fmt.Errorf("random preimage b: %w", err)
	}
	return Assign(&a, &b)
}
