package recursion

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// Circuit is the outer Groth16 verifier circuit: it verifies a Groth16 proof
// of a fixed inner circuit, checked with grosh26's ring pairing rather than
// gnark's own.
//
// The inner verifying key is baked in as compile-time constants -- set it
// with [NewCircuit] before compiling, and rebuild the placeholder with the
// same key when constructing an unassigned circuit for compilation.
type Circuit struct {
	Proof         Proof         `gnark:",secret"`
	PublicWitness PublicWitness `gnark:",public"`

	vk *VerifyingKey
}

// NewCircuit returns a [Circuit] with the inner verifying key baked in. Use
// it both for the witness assignment and for the unassigned circuit passed to
// [frontend.Compile]: the verifying key is a Go-level constant, not part of
// the witness, so both need the same one.
//
// nbPublic is the inner circuit's number of public inputs (excluding the
// implicit one-wire); it sizes the placeholder PublicWitness for compilation.
func NewCircuit(vk *VerifyingKey, nbPublic int) *Circuit {
	return &Circuit{
		PublicWitness: PublicWitness{Public: make([]Scalar, nbPublic)},
		vk:            vk,
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if c.vk == nil {
		return fmt.Errorf("outer circuit: no verifying key; build with NewCircuit")
	}
	verifier, err := NewVerifier(api, c.vk)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.Proof, c.PublicWitness)
}
