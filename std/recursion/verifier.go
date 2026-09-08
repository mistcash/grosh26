// Package recursion holds the outer Verifier circuit: a Groth16 verifier for
// gnark BN254 proofs, checked with grosh26's ring pairing instead of gnark's
// own. v0.1 handles inner circuits that carry no BSB22 commitments of their
// own -- the poseidon demo's case.
package recursion

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16backend "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/grosh26/std/ring_bn254"
)

type (
	G1Affine = sw_bn254.G1Affine
	G2Affine = sw_bn254.G2Affine
	GTEl     = sw_bn254.GTEl
	Scalar   = sw_bn254.Scalar
)

// VerifyingKey is the inner circuit's Groth16 verifying key, in the native
// (off-circuit) point types. Build one with [NewVerifyingKey] and pass it to
// [NewVerifier] to bake it into the outer circuit as compile-time constants.
//
// It deliberately does not store gnark's in-circuit point types: those are
// normally built by [sw_bn254.NewG1Affine] et al. via emulated.ValueOf.
// [NewVerifier] builds the in-circuit constants inside Define the same way,
// matching that convention.
type VerifyingKey struct {
	alphaNeg bn254.G1Affine
	beta     bn254.G2Affine
	gammaNeg bn254.G2Affine
	deltaNeg bn254.G2Affine
	k        []bn254.G1Affine // indexed by public input position, k[0] for the constant term
}

// NewVerifyingKey converts a native Groth16 verifying key for use as the
// outer circuit's baked-in constants. vk must carry no BSB22 commitments: v0.1
// does not support recursively verifying inner circuits that draw their own.
func NewVerifyingKey(vk *groth16backend.VerifyingKey) (*VerifyingKey, error) {
	if len(vk.CommitmentKeys) > 0 {
		return nil, fmt.Errorf("outer verifier: inner circuits with BSB22 commitments are not supported (got %d)", len(vk.CommitmentKeys))
	}
	var alphaNeg bn254.G1Affine
	alphaNeg.Neg(&vk.G1.Alpha)
	var gammaNeg, deltaNeg bn254.G2Affine
	gammaNeg.Neg(&vk.G2.Gamma)
	deltaNeg.Neg(&vk.G2.Delta)
	k := make([]bn254.G1Affine, len(vk.G1.K))
	copy(k, vk.G1.K)
	return &VerifyingKey{
		alphaNeg: alphaNeg,
		beta:     vk.G2.Beta,
		gammaNeg: gammaNeg,
		deltaNeg: deltaNeg,
		k:        k,
	}, nil
}

// Proof is the inner circuit's Groth16 proof, as outer-circuit witness
// variables. Build one with [ValueOfProof].
type Proof struct {
	Ar, Krs G1Affine
	Bs      G2Affine
}

// ValueOfProof returns the outer-circuit witness for a native Groth16 proof.
// The proof must carry no BSB22 commitments; see [NewVerifyingKey].
func ValueOfProof(proof *groth16backend.Proof) (Proof, error) {
	if len(proof.Commitments) > 0 {
		return Proof{}, fmt.Errorf("outer verifier: proofs with BSB22 commitments are not supported (got %d)", len(proof.Commitments))
	}
	return Proof{
		Ar:  sw_bn254.NewG1Affine(proof.Ar),
		Krs: sw_bn254.NewG1Affine(proof.Krs),
		Bs:  sw_bn254.NewG2Affine(proof.Bs),
	}, nil
}

// PublicWitness is the inner circuit's public inputs, as outer-circuit
// witness variables (excluding the implicit one-wire). Build one with
// [ValueOfPublicWitness].
type PublicWitness struct {
	Public []Scalar
}

// ValueOfPublicWitness returns the outer-circuit witness for the inner
// circuit's public inputs.
func ValueOfPublicWitness(public []fr.Element) PublicWitness {
	scalars := make([]Scalar, len(public))
	for i := range public {
		scalars[i] = sw_bn254.NewScalar(public[i])
	}
	return PublicWitness{Public: scalars}
}

// Verifier verifies Groth16 proofs against a fixed [VerifyingKey], using
// grosh26's ring pairing rather than gnark's own.
type Verifier struct {
	curve   *sw_emulated.Curve[emparams.BN254Fp, emparams.BN254Fr]
	pairing *ring_bn254.Pairing

	// alphaBeta is the e(α,β)⁻¹ Miller loop value. Both of its points come
	// from the verifying key, so it is computed once, here, and folded into
	// the product as the previous value rather than a pass through the loop.
	// gamma and delta carry precomputed lines, so their ladders and subgroup
	// checks leave the circuit; see sw_bn254.NewG2AffineFixed.
	alphaBeta GTEl
	gamma     G2Affine
	delta     G2Affine

	// the K points as in-circuit constants.
	k []G1Affine
}

// NewVerifier returns a verifier for proofs against vk, baking vk's points in
// as compile-time constants.
func NewVerifier(api frontend.API, vk *VerifyingKey) (*Verifier, error) {
	// the ring checker has to be registered before anything else creates an
	// emulated field, see the note on NewExt12 in std/ring_bn254/ring.go.
	pairing, err := ring_bn254.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	k := make([]G1Affine, len(vk.k))
	for i := range k {
		k[i] = sw_bn254.NewG1Affine(vk.k[i])
	}
	// α and β are both fixed, so e(α,β)⁻¹ never reaches the Miller loop: its
	// Miller loop value is computed here and folded into the product as the
	// previous value. Both points are checked here, off-circuit -- neither
	// reaches a ladder or a subgroup check in-circuit.
	//
	// MillerLoopFixedQ, not MillerLoop: the projective loop's raw value
	// carries the lines' Z factors, which this check never removes.
	if vk.alphaNeg.IsInfinity() {
		return nil, fmt.Errorf("alpha point is the point at infinity")
	}
	if !vk.alphaNeg.IsInSubGroup() {
		return nil, fmt.Errorf("alpha point is not on the curve")
	}
	if vk.beta.IsInfinity() {
		return nil, fmt.Errorf("beta point is the point at infinity")
	}
	if !vk.beta.IsInSubGroup() {
		return nil, fmt.Errorf("beta point is not in the G2 subgroup")
	}
	ml, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{vk.alphaNeg},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(vk.beta)},
	)
	if err != nil {
		return nil, fmt.Errorf("alpha-beta miller loop: %w", err)
	}
	// γ and δ carry precomputed lines. NewG2AffineFixed panics on a point
	// outside the subgroup, like gnark.
	gamma := sw_bn254.NewG2AffineFixed(vk.gammaNeg)
	delta := sw_bn254.NewG2AffineFixed(vk.deltaNeg)
	return &Verifier{
		curve:     curve,
		pairing:   pairing,
		alphaBeta: sw_bn254.NewGTEl(ml),
		gamma:     gamma,
		delta:     delta,
		k:         k,
	}, nil
}

// AssertProof asserts that proof is a valid Groth16 proof of the inner
// circuit's statement against publicWitness, under the verifier's fixed
// verifying key.
//
// The Groth16 pairing identity e(A,B)·e(α,β)⁻¹·e(L,γ)⁻¹·e(C,δ)⁻¹ = 1 is
// checked as a single 4-term [ring_bn254.Pairing.PairingCheck] -- the
// verifying key's γ, δ (and the folded-in α) are already negated in
// [NewVerifyingKey], so the identity becomes a plain product-equals-one.
//
// Only the first term is a full pairing: A, B are the proof's. Everything
// else is fixed by the verifying key, so the identity costs one Miller loop
// over three G1 points rather than four in-circuit [6x₀+2]Q ladders:
//
//   - e(L,γ)⁻¹ and e(C,δ)⁻¹ are fixed-Q pairs. γ and δ never vary, so their
//     line evaluations are precomputed off-circuit and the ladder and the G2
//     subgroup check for them leave the circuit entirely.
//   - e(α,β)⁻¹ has both points fixed, so its Miller loop value is a
//     compile-time constant, folded into the product as the previous value.
//
// AssertProof itself has no notion of BSB22 commitments -- there is no
// Commitments field on [Proof] and no PoK check here. The "no commitments"
// restriction documented on [NewVerifyingKey] and [ValueOfProof] holds only
// because their rejection of vk.CommitmentKeys/proof.Commitments keeps len(v.k)
// and len(publicWitness.Public) matching what an inner circuit without
// commitments produces; it is not independently enforced below.
func (v *Verifier) AssertProof(proof Proof, publicWitness PublicWitness) error {
	if len(publicWitness.Public) != len(v.k)-1 {
		return fmt.Errorf("invalid witness size, got %d, expected %d", len(publicWitness.Public), len(v.k)-1)
	}

	// K-sum: k[0] + Σ k[i+1]·public[i]. The k[i] are compile-time constants
	// and the public[i] are prover-influenced, so nothing rules out two
	// summands landing on equal or negated points (a malicious prover can
	// choose public-input scalars, and public-input scalars can also be
	// chosen adversarially inside a recursively-verified circuit) -- there is
	// no argument available that would let this run through v.curve's
	// incomplete Add safely. Route the scalar-multiple terms through
	// MultiScalarMul, matching gnark's own reference Groth16 verifier
	// (std/recursion/groth16/verifier.go, IsValidProof): with no
	// WithIncompleteArithmetic option, it folds terms via AddUnified, so the
	// whole accumulation uses complete addition. Fold in the constant term
	// k[0] with AddUnified rather than gnark's plain Add (gnark's Add there
	// is safe only because K[0] is a fixed constant summed once at the end;
	// AddUnified costs the same for a single fold and removes even that
	// residual incomplete edge).
	kTerms := make([]*G1Affine, len(v.k)-1)
	for i := range kTerms {
		kTerms[i] = &v.k[i+1]
	}
	kScalars := make([]*Scalar, len(publicWitness.Public))
	for i := range publicWitness.Public {
		kScalars[i] = &publicWitness.Public[i]
	}
	kSum, err := v.curve.MultiScalarMul(kTerms, kScalars)
	if err != nil {
		return fmt.Errorf("k-sum multi scalar mul: %w", err)
	}
	kSum = v.curve.AddUnified(kSum, &v.k[0])

	v.pairing.AssertIsOnG1(&proof.Ar)
	v.pairing.AssertIsOnG1(&proof.Krs)
	v.pairing.AssertIsOnG2(&proof.Bs)

	return v.pairing.PairingCheck(
		[]*G1Affine{&proof.Ar, kSum, &proof.Krs},
		[]*G2Affine{&proof.Bs, &v.gamma, &v.delta},
		&v.alphaBeta,
	)
}
