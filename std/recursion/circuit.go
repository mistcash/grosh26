package recursion

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Circuit is the outer Groth16 verifier circuit: it verifies a Groth16 proof
// of a fixed inner circuit over the curve with base field F, scalar field S,
// G2 type G2El and target group GtEl. [BN254Circuit] and [BLS12381Circuit]
// are the two supported instances.
//
// The inner verifying key is baked in as compile-time constants -- set it
// with [NewCircuit] before compiling, and rebuild the placeholder with the
// same key when constructing an unassigned circuit for compilation.
type Circuit[F, S emulated.FieldParams, G2El, GtEl any] struct {
	Proof         Proof[F, G2El]   `gnark:",secret"`
	PublicWitness PublicWitness[S] `gnark:",public"`

	vk  *VerifyingKey
	cfg config
}

type (
	BN254Circuit    = Circuit[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl]
	BLS12381Circuit = Circuit[emparams.BLS12381Fp, emparams.BLS12381Fr, sw_bls12381.G2Affine, sw_bls12381.GTEl]
)

type config struct {
	gnarkPairing bool
}

// Option configures a [Circuit] or [Verifier].
type Option func(*config)

// WithGnarkPairing checks the pairing identity with gnark's own pairing
// instead of the ring pairing: the same statement, for comparison.
func WithGnarkPairing() Option {
	return func(c *config) { c.gnarkPairing = true }
}

// NewCircuit returns a [Circuit] with the inner verifying key baked in. Use
// it both for the witness assignment and for the unassigned circuit passed to
// [frontend.Compile]: the verifying key is a Go-level constant, not part of
// the witness, so both need the same one.
func NewCircuit[F, S emulated.FieldParams, G2El, GtEl any](vk *VerifyingKey, opts ...Option) *Circuit[F, S, G2El, GtEl] {
	c := &Circuit[F, S, G2El, GtEl]{
		PublicWitness: PublicWitness[S]{Public: make([]emulated.Element[S], vk.nbPublic)},
		vk:            vk,
	}
	for _, o := range opts {
		o(&c.cfg)
	}
	return c
}

// NewBN254Circuit is [NewCircuit] for BN254 inner proofs.
func NewBN254Circuit(vk *VerifyingKey, opts ...Option) *BN254Circuit {
	return NewCircuit[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl](vk, opts...)
}

// NewBLS12381Circuit is [NewCircuit] for BLS12-381 inner proofs.
func NewBLS12381Circuit(vk *VerifyingKey, opts ...Option) *BLS12381Circuit {
	return NewCircuit[emparams.BLS12381Fp, emparams.BLS12381Fr, sw_bls12381.G2Affine, sw_bls12381.GTEl](vk, opts...)
}

// Assign sets the witness to a native inner proof and the inner circuit's
// public witness. The proof must carry no BSB22 commitments; see
// [NewVerifyingKey].
func (c *Circuit[F, S, G2El, GtEl]) Assign(proof groth16.Proof, publicWitness witness.Witness) error {
	p, err := valueOfProof[F, G2El](proof)
	if err != nil {
		return err
	}
	w, err := valueOfPublicWitness[S](publicWitness)
	if err != nil {
		return err
	}
	if c.vk != nil && len(w.Public) != c.vk.nbPublic {
		return fmt.Errorf("outer circuit: got %d public inputs, verifying key expects %d", len(w.Public), c.vk.nbPublic)
	}
	c.Proof, c.PublicWitness = p, w
	return nil
}

func (c *Circuit[F, S, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[F, S, G2El, GtEl](api, c.vk, func(cfg *config) { *cfg = c.cfg })
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.Proof, c.PublicWitness)
}
