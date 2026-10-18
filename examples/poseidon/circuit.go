// Package poseidon holds the inner circuit for grosh26's recursion demo: a
// proof of knowledge of a poseidon 2→1 compression preimage, over BN254 or
// BLS12-381.
package poseidon

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	blsposeidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bnposeidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

// Compress computes the poseidon2 2→1 compression of a and b natively over
// curve's scalar field, using the same width-2 default parameters the
// circuit's permutation uses.
func Compress(curve ecc.ID, a, b *big.Int) (*big.Int, error) {
	var digest []byte
	var err error
	switch curve {
	case ecc.BN254:
		var x, y bnfr.Element
		xb, yb := x.SetBigInt(a).Bytes(), y.SetBigInt(b).Bytes()
		digest, err = bnposeidon2.NewDefaultPermutation().Compress(xb[:], yb[:])
	case ecc.BLS12_381:
		var x, y blsfr.Element
		xb, yb := x.SetBigInt(a).Bytes(), y.SetBigInt(b).Bytes()
		digest, err = blsposeidon2.NewDefaultPermutation().Compress(xb[:], yb[:])
	default:
		return nil, fmt.Errorf("unsupported curve %s", curve)
	}
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}
	// the digest is a canonical field element, big-endian
	return new(big.Int).SetBytes(digest), nil
}

// Assign builds a witness for the given preimage.
func Assign(curve ecc.ID, a, b *big.Int) (*Circuit, error) {
	digest, err := Compress(curve, a, b)
	if err != nil {
		return nil, err
	}
	return &Circuit{A: a, B: b, Digest: digest}, nil
}

// AssignRandom builds a witness for a random preimage.
func AssignRandom(curve ecc.ID) (*Circuit, error) {
	a, err := rand.Int(rand.Reader, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("random preimage a: %w", err)
	}
	b, err := rand.Int(rand.Reader, curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("random preimage b: %w", err)
	}
	return Assign(curve, a, b)
}

// Prove compiles the circuit over curve's scalar field, runs its Groth16
// setup and proves a random preimage, returning what an outer circuit needs:
// the verifying key, the proof and the public witness.
func Prove(curve ecc.ID) (groth16.VerifyingKey, groth16.Proof, witness.Witness, error) {
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup: %w", err)
	}
	assignment, err := AssignRandom(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	full, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("witness: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("prove: %w", err)
	}
	public, err := full.Public()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("public witness: %w", err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		return nil, nil, nil, fmt.Errorf("verify: %w", err)
	}
	return vk, proof, public, nil
}
