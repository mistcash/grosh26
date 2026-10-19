// Package mimc holds the inner circuit for polyring's recursion demo: a proof
// of knowledge of a MiMC preimage, over BN254 or BLS12-381.
package mimc

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/hash/all"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// Circuit proves knowledge of A, B for which Digest = MiMC(A, B). MiMC picks
// its parameters from the curve the circuit is compiled over, so one circuit
// serves both inner curves. It carries no commitments of its own; the outer
// circuit that verifies its proof draws the three BSB22 commitments.
type Circuit struct {
	A, B   frontend.Variable `gnark:",secret"`
	Digest frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	h, err := stdmimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("new mimc: %w", err)
	}
	h.Write(c.A, c.B)
	api.AssertIsEqual(h.Sum(), c.Digest)
	return nil
}

// Hash computes MiMC(a, b) natively over curve's scalar field. Both inputs
// have to be reduced.
func Hash(curve ecc.ID, a, b *big.Int) (*big.Int, error) {
	h := hash.NewHash("MIMC_" + strings.ToUpper(curve.String()))
	for _, x := range []*big.Int{a, b} {
		if _, err := h.Write(x.FillBytes(make([]byte, 32))); err != nil {
			return nil, fmt.Errorf("hash: %w", err)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// Assign builds a witness for the given preimage.
func Assign(curve ecc.ID, a, b *big.Int) (*Circuit, error) {
	digest, err := Hash(curve, a, b)
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
