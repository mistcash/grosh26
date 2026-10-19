// Package gnarkpairing provides the outer verifier circuit of
// [github.com/mistcash/polyring/std/recursion] checked with gnark's own
// in-circuit pairing instead of polyring's ring pairing.
//
// It is the baseline polyring is measured against: the same circuit and the
// same statement, differing only in the pairing check. The pairing
// implementation is what changes the shape of the circuit, so the comparison
// is only meaningful if everything else is held fixed.
//
// A user who wants to A/B the two in their own project can import this
// alongside std/recursion and get both circuits from the same verifying key.
package gnarkpairing

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/recursion"
)

// Pairing adapts gnark's sw_bn254 / sw_bls12381 pairing to
// [recursion.Pairing].
type Pairing[F emulated.FieldParams, G2El, GtEl any] struct {
	p interface {
		AssertIsOnG1(*recursion.G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*recursion.G1Affine[F], []*G2El, *GtEl)
	}
}

// AssertIsOnG1 asserts P is on the curve and in the prime-order subgroup.
func (g Pairing[F, G2El, GtEl]) AssertIsOnG1(P *recursion.G1Affine[F]) {
	g.p.AssertIsOnG1(P)
}

// PairingCheck asserts the Groth16 pairing identity holds.
func (g Pairing[F, G2El, GtEl]) PairingCheck(P []*recursion.G1Affine[F], Q []*G2El, previous *GtEl) error {
	g.p.AssertMultiMillerLoopAndFinalExpIsOne(P, Q, previous)
	return nil
}

// NewPairing returns gnark's pairing over the curve G2El belongs to.
//
// It has to be created before anything else in the circuit creates an
// emulated field, for the same reason as in [recursion.NewVerifier]: the
// emulated field gnark's pairing opens has to come up in the same order as
// the ring pairing's, or the two circuits would not be comparable.
func NewPairing[F emulated.FieldParams, G2El, GtEl any](api frontend.API) (recursion.Pairing[F, G2El, GtEl], error) {
	var (
		p   any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		p, err = sw_bn254.NewPairing(api)
	case *sw_bls12381.G2Affine:
		p, err = sw_bls12381.NewPairing(api)
	default:
		return nil, fmt.Errorf("unsupported G2 type %T", (*G2El)(nil))
	}
	if err != nil {
		return nil, err
	}
	return Pairing[F, G2El, GtEl]{p: p.(interface {
		AssertIsOnG1(*recursion.G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*recursion.G1Affine[F], []*G2El, *GtEl)
	})}, nil
}

// Circuit is [recursion.Circuit] checked with gnark's pairing: the embedded
// circuit supplies the witness and Assign, Define swaps the pairing.
type Circuit[F, S emulated.FieldParams, G2El, GtEl any] struct {
	recursion.Circuit[F, S, G2El, GtEl]
	vk *recursion.VerifyingKey
}

// NewCircuit returns the baseline circuit for vk, checked with gnark's
// pairing.
func NewCircuit[F, S emulated.FieldParams, G2El, GtEl any](vk *recursion.VerifyingKey) *Circuit[F, S, G2El, GtEl] {
	return &Circuit[F, S, G2El, GtEl]{Circuit: *recursion.NewCircuit[F, S, G2El, GtEl](vk), vk: vk}
}

// Define builds the verifier with gnark's pairing and checks the proof.
func (c *Circuit[F, S, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := NewPairing[F, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new gnark pairing: %w", err)
	}
	v, err := recursion.NewVerifierWithPairing[F, S, G2El, GtEl](api, c.vk, pr)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return v.AssertProof(c.Proof, c.PublicWitness)
}
