package profile

// The Groth16 verifier of std/recursion on gnark's own pairing, the baseline
// the ring pairing is measured against: the same circuit and statement,
// differing only in the pairing check.

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/recursion"
)

// gnarkPairing adapts gnark's sw_bn254 / sw_bls12381 pairing to
// [recursion.Pairing].
type gnarkPairing[F emulated.FieldParams, G2El, GtEl any] struct {
	p interface {
		AssertIsOnG1(*recursion.G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*recursion.G1Affine[F], []*G2El, *GtEl)
	}
}

func (g gnarkPairing[F, G2El, GtEl]) AssertIsOnG1(P *recursion.G1Affine[F]) { g.p.AssertIsOnG1(P) }
func (g gnarkPairing[F, G2El, GtEl]) PairingCheck(P []*recursion.G1Affine[F], Q []*G2El, previous *GtEl) error {
	g.p.AssertMultiMillerLoopAndFinalExpIsOne(P, Q, previous)
	return nil
}

func newGnarkPairing[F emulated.FieldParams, G2El, GtEl any](api frontend.API) (recursion.Pairing[F, G2El, GtEl], error) {
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
	return gnarkPairing[F, G2El, GtEl]{p: p.(interface {
		AssertIsOnG1(*recursion.G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*recursion.G1Affine[F], []*G2El, *GtEl)
	})}, nil
}

// gnarkCircuit is [recursion.Circuit] checked with gnark's pairing: the
// embedded circuit supplies the witness and Assign, Define swaps the pairing.
type gnarkCircuit[F, S emulated.FieldParams, G2El, GtEl any] struct {
	recursion.Circuit[F, S, G2El, GtEl]
	vk *recursion.VerifyingKey
}

func newGnarkCircuit[F, S emulated.FieldParams, G2El, GtEl any](vk *recursion.VerifyingKey) *gnarkCircuit[F, S, G2El, GtEl] {
	return &gnarkCircuit[F, S, G2El, GtEl]{Circuit: *recursion.NewCircuit[F, S, G2El, GtEl](vk), vk: vk}
}

func (c *gnarkCircuit[F, S, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newGnarkPairing[F, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new gnark pairing: %w", err)
	}
	v, err := recursion.NewVerifierWithPairing[F, S, G2El, GtEl](api, c.vk, pr)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return v.AssertProof(c.Proof, c.PublicWitness)
}
