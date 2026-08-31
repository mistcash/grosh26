// Package recursion holds the outer Verifier circuit: a Groth16 verifier for
// gnark BN254 proofs, checked with grosh26's ring pairing instead of gnark's
// own. v0.1 handles inner circuits that carry no BSB22 commitments of their
// own -- the poseidon demo's case.
package recursion

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16backend "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/grosh26/std/ring_bn254"
)

type (
	G1Affine = sw_bn254.G1Affine
	G2Affine = sw_bn254.G2Affine
	Scalar   = sw_bn254.Scalar
)

// VerifyingKey is the inner circuit's Groth16 verifying key, in the native
// (off-circuit) point types. Build one with [NewVerifyingKey] and pass it to
// [NewVerifier] to bake it into the outer circuit as compile-time constants.
//
// It deliberately does not store gnark's in-circuit point types: those are
// built by [sw_bn254.NewG1Affine] et al. via [emulated.ValueOf], which only
// allocates real limbs once gnark's schema walker calls Element.Initialize on
// it during witness parsing. A verifying key lives outside the witness --
// stashed in an unexported field, it would never be walked, and the pairing
// check would silently run against uninitialized (wrong) limbs instead of
// failing loudly. [NewVerifier] builds the real in-circuit constants inside
// Define instead, with [emulated.Field.NewElement], the same way
// [sw_emulated.New] builds its own hardcoded curve generator.
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

	// the verifying key's points, built once as real in-circuit constants;
	// see the note on [VerifyingKey] for why this has to happen here rather
	// than ahead of time.
	alphaNeg G1Affine
	beta     G2Affine
	gammaNeg G2Affine
	deltaNeg G2Affine
	k        []G1Affine
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
	fp, err := emulated.NewField[emparams.BN254Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base field: %w", err)
	}
	k := make([]G1Affine, len(vk.k))
	for i := range k {
		k[i] = constG1(fp, vk.k[i])
	}
	return &Verifier{
		curve:    curve,
		pairing:  pairing,
		alphaNeg: constG1(fp, vk.alphaNeg),
		beta:     constG2(fp, vk.beta),
		gammaNeg: constG2(fp, vk.gammaNeg),
		deltaNeg: constG2(fp, vk.deltaNeg),
		k:        k,
	}, nil
}

// constG1 builds p as an in-circuit constant: real limbs, allocated now,
// rather than deferred to witness parsing.
func constG1(fp *emulated.Field[emparams.BN254Fp], p bn254.G1Affine) G1Affine {
	x, y := new(big.Int), new(big.Int)
	p.X.BigInt(x)
	p.Y.BigInt(y)
	return G1Affine{X: *fp.NewElement(x), Y: *fp.NewElement(y)}
}

// constG2 builds p as an in-circuit constant; see [constG1].
func constG2(fp *emulated.Field[emparams.BN254Fp], p bn254.G2Affine) G2Affine {
	x0, x1, y0, y1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	p.X.A0.BigInt(x0)
	p.X.A1.BigInt(x1)
	p.Y.A0.BigInt(y0)
	p.Y.A1.BigInt(y1)
	var g G2Affine
	g.P.X.A0 = *fp.NewElement(x0)
	g.P.X.A1 = *fp.NewElement(x1)
	g.P.Y.A0 = *fp.NewElement(y0)
	g.P.Y.A1 = *fp.NewElement(y1)
	return g
}

// AssertProof asserts that proof is a valid Groth16 proof of the inner
// circuit's statement against publicWitness, under the verifier's fixed
// verifying key.
//
// The Groth16 pairing identity e(A,B)·e(α,β)⁻¹·e(L,γ)⁻¹·e(C,δ)⁻¹ = 1 is
// checked as a single 4-term [ring_bn254.Pairing.PairingCheck] -- the
// verifying key's γ, δ (and the folded-in α) are already negated in
// [NewVerifyingKey], so the identity becomes a plain product-equals-one.
func (v *Verifier) AssertProof(proof Proof, publicWitness PublicWitness) error {
	if len(publicWitness.Public) != len(v.k)-1 {
		return fmt.Errorf("invalid witness size, got %d, expected %d", len(publicWitness.Public), len(v.k)-1)
	}

	kSum := &v.k[0]
	for i := range publicWitness.Public {
		term := v.curve.ScalarMul(&v.k[i+1], &publicWitness.Public[i])
		kSum = v.curve.Add(kSum, term)
	}

	v.pairing.AssertIsOnG1(&proof.Ar)
	v.pairing.AssertIsOnG1(&proof.Krs)
	v.pairing.AssertIsOnG2(&proof.Bs)

	return v.pairing.PairingCheck(
		[]*G1Affine{&proof.Ar, &v.alphaNeg, kSum, &proof.Krs},
		[]*G2Affine{&proof.Bs, &v.beta, &v.gammaNeg, &v.deltaNeg},
	)
}
