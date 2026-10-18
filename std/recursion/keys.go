package recursion

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// VerifyingKey is the inner circuit's Groth16 verifying key, prepared for use
// as the outer circuit's baked-in constants. Build one with
// [NewVerifyingKey].
//
// It deliberately keeps the native (off-circuit) points rather than gnark's
// in-circuit types: emulated elements cache circuit state once used, so the
// in-circuit constants are rebuilt inside every Define instead.
type VerifyingKey struct {
	nbPublic int
	native   any // *bn254Key or *bls12381Key
}

// Proof is the inner circuit's Groth16 proof, as outer-circuit witness
// variables. [Circuit.Assign] fills it in.
type Proof[F emulated.FieldParams, G2El any] struct {
	Ar, Krs G1Affine[F]
	Bs      G2El
}

// PublicWitness is the inner circuit's public inputs, as outer-circuit
// witness variables (excluding the implicit one-wire). [Circuit.Assign] fills
// it in.
type PublicWitness[S emulated.FieldParams] struct {
	Public []emulated.Element[S]
}

// vkConstants are a verifying key's points as in-circuit constants: γ and δ
// negated and carrying precomputed lines, and α, β folded into the previous
// Miller loop value e(α,β)⁻¹.
type vkConstants[F emulated.FieldParams, G2El, GtEl any] struct {
	alphaBeta          GtEl
	gammaNeg, deltaNeg G2El
	k                  []G1Affine[F] // indexed by public input position, k[0] for the constant term
}

// NewVerifyingKey prepares a native BN254 or BLS12-381 Groth16 verifying key
// for use as the outer circuit's baked-in constants. vk must carry no BSB22
// commitments: v0.1 does not support recursively verifying inner circuits
// that draw their own.
//
// β, γ and δ skip the in-circuit ladder and subgroup check, so nothing in the
// circuit would catch a malformed key point: they, and α, are checked here.
func NewVerifyingKey(vk groth16.VerifyingKey) (*VerifyingKey, error) {
	switch vk := vk.(type) {
	case *groth16bn254.VerifyingKey:
		return newBN254Key(vk)
	case *groth16bls12381.VerifyingKey:
		return newBLS12381Key(vk)
	default:
		return nil, fmt.Errorf("outer verifier: unsupported verifying key %T", vk)
	}
}

// constantsOf builds vk's in-circuit constants, failing when vk is for a
// different curve than the circuit.
func constantsOf[F emulated.FieldParams, G2El, GtEl any](vk *VerifyingKey) (*vkConstants[F, G2El, GtEl], error) {
	if vk == nil {
		return nil, fmt.Errorf("outer circuit: no verifying key; build with NewCircuit")
	}
	var c any
	switch n := vk.native.(type) {
	case *bn254Key:
		c = n.constants()
	case *bls12381Key:
		c = n.constants()
	}
	consts, ok := c.(*vkConstants[F, G2El, GtEl])
	if !ok {
		return nil, fmt.Errorf("outer circuit: verifying key is for another curve than G2 type %T", (*G2El)(nil))
	}
	return consts, nil
}

// checkKeyPoints checks α, β, γ and δ are in their subgroups and not the point
// at infinity.
func checkKeyPoints(alpha, beta, gamma, delta interface {
	IsInfinity() bool
	IsInSubGroup() bool
}) error {
	for _, p := range []struct {
		name string
		pt   interface {
			IsInfinity() bool
			IsInSubGroup() bool
		}
	}{{"alpha", alpha}, {"beta", beta}, {"gamma", gamma}, {"delta", delta}} {
		if p.pt.IsInfinity() {
			return fmt.Errorf("outer verifier: %s point is the point at infinity", p.name)
		}
		if !p.pt.IsInSubGroup() {
			group := "G2"
			if p.name == "alpha" {
				group = "G1"
			}
			return fmt.Errorf("outer verifier: %s point is not in the %s subgroup", p.name, group)
		}
	}
	return nil
}

type bn254Key struct {
	alphaBeta          bn254.GT
	gammaNeg, deltaNeg bn254.G2Affine
	k                  []bn254.G1Affine
}

func newBN254Key(vk *groth16bn254.VerifyingKey) (*VerifyingKey, error) {
	if len(vk.CommitmentKeys) > 0 {
		return nil, fmt.Errorf("outer verifier: inner circuits with BSB22 commitments are not supported (got %d)", len(vk.CommitmentKeys))
	}
	if err := checkKeyPoints(&vk.G1.Alpha, &vk.G2.Beta, &vk.G2.Gamma, &vk.G2.Delta); err != nil {
		return nil, err
	}
	key := &bn254Key{k: append([]bn254.G1Affine(nil), vk.G1.K...)}
	key.gammaNeg.Neg(&vk.G2.Gamma)
	key.deltaNeg.Neg(&vk.G2.Delta)
	// MillerLoopFixedQ, not MillerLoop: the projective loop's raw value
	// carries the lines' Z factors, which the pairing check never removes.
	var alphaNeg bn254.G1Affine
	alphaNeg.Neg(&vk.G1.Alpha)
	ml, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{alphaNeg},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(vk.G2.Beta)},
	)
	if err != nil {
		return nil, fmt.Errorf("alpha-beta miller loop: %w", err)
	}
	key.alphaBeta = ml
	return &VerifyingKey{nbPublic: len(vk.G1.K) - 1, native: key}, nil
}

func (key *bn254Key) constants() *vkConstants[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl] {
	k := make([]G1Affine[emparams.BN254Fp], len(key.k))
	for i := range k {
		k[i] = sw_bn254.NewG1Affine(key.k[i])
	}
	return &vkConstants[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl]{
		alphaBeta: sw_bn254.NewGTEl(key.alphaBeta),
		gammaNeg:  sw_bn254.NewG2AffineFixed(key.gammaNeg),
		deltaNeg:  sw_bn254.NewG2AffineFixed(key.deltaNeg),
		k:         k,
	}
}

type bls12381Key struct {
	alphaBeta          bls12381.GT
	gammaNeg, deltaNeg bls12381.G2Affine
	k                  []bls12381.G1Affine
}

func newBLS12381Key(vk *groth16bls12381.VerifyingKey) (*VerifyingKey, error) {
	if len(vk.CommitmentKeys) > 0 {
		return nil, fmt.Errorf("outer verifier: inner circuits with BSB22 commitments are not supported (got %d)", len(vk.CommitmentKeys))
	}
	if err := checkKeyPoints(&vk.G1.Alpha, &vk.G2.Beta, &vk.G2.Gamma, &vk.G2.Delta); err != nil {
		return nil, err
	}
	key := &bls12381Key{k: append([]bls12381.G1Affine(nil), vk.G1.K...)}
	key.gammaNeg.Neg(&vk.G2.Gamma)
	key.deltaNeg.Neg(&vk.G2.Delta)
	var alphaNeg bls12381.G1Affine
	alphaNeg.Neg(&vk.G1.Alpha)
	ml, err := bls12381.MillerLoopFixedQ(
		[]bls12381.G1Affine{alphaNeg},
		[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{bls12381.PrecomputeLines(vk.G2.Beta)},
	)
	if err != nil {
		return nil, fmt.Errorf("alpha-beta miller loop: %w", err)
	}
	// gnark's BLS12-381 pairing check takes the previous value conjugated,
	// matching the unconjugated loop it runs in-circuit
	key.alphaBeta.Conjugate(&ml)
	return &VerifyingKey{nbPublic: len(vk.G1.K) - 1, native: key}, nil
}

func (key *bls12381Key) constants() *vkConstants[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl] {
	k := make([]G1Affine[emparams.BLS12381Fp], len(key.k))
	for i := range k {
		k[i] = sw_bls12381.NewG1Affine(key.k[i])
	}
	return &vkConstants[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		alphaBeta: sw_bls12381.NewGTEl(key.alphaBeta),
		gammaNeg:  sw_bls12381.NewG2AffineFixed(key.gammaNeg),
		deltaNeg:  sw_bls12381.NewG2AffineFixed(key.deltaNeg),
		k:         k,
	}
}

// valueOfProof returns the outer-circuit witness for a native Groth16 proof,
// which must carry no BSB22 commitments; see [NewVerifyingKey].
func valueOfProof[F emulated.FieldParams, G2El any](proof groth16.Proof) (Proof[F, G2El], error) {
	var p any
	switch proof := proof.(type) {
	case *groth16bn254.Proof:
		if len(proof.Commitments) > 0 {
			return Proof[F, G2El]{}, fmt.Errorf("outer verifier: proofs with BSB22 commitments are not supported (got %d)", len(proof.Commitments))
		}
		p = Proof[emparams.BN254Fp, sw_bn254.G2Affine]{
			Ar:  sw_bn254.NewG1Affine(proof.Ar),
			Krs: sw_bn254.NewG1Affine(proof.Krs),
			Bs:  sw_bn254.NewG2Affine(proof.Bs),
		}
	case *groth16bls12381.Proof:
		if len(proof.Commitments) > 0 {
			return Proof[F, G2El]{}, fmt.Errorf("outer verifier: proofs with BSB22 commitments are not supported (got %d)", len(proof.Commitments))
		}
		p = Proof[emparams.BLS12381Fp, sw_bls12381.G2Affine]{
			Ar:  sw_bls12381.NewG1Affine(proof.Ar),
			Krs: sw_bls12381.NewG1Affine(proof.Krs),
			Bs:  sw_bls12381.NewG2Affine(proof.Bs),
		}
	}
	res, ok := p.(Proof[F, G2El])
	if !ok {
		return res, fmt.Errorf("outer verifier: proof %T is not for G2 type %T", proof, (*G2El)(nil))
	}
	return res, nil
}

// valueOfPublicWitness returns the outer-circuit witness for the inner
// circuit's public inputs.
func valueOfPublicWitness[S emulated.FieldParams](public witness.Witness) (PublicWitness[S], error) {
	var values []*big.Int
	switch vec := public.Vector().(type) {
	case bnfr.Vector:
		for i := range vec {
			values = append(values, vec[i].BigInt(new(big.Int)))
		}
	case blsfr.Vector:
		for i := range vec {
			values = append(values, vec[i].BigInt(new(big.Int)))
		}
	default:
		return PublicWitness[S]{}, fmt.Errorf("outer verifier: unsupported public witness %T", vec)
	}
	res := PublicWitness[S]{Public: make([]emulated.Element[S], len(values))}
	for i, v := range values {
		res.Public[i] = emulated.ValueOf[S](v)
	}
	return res, nil
}
