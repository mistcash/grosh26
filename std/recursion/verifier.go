// Package recursion holds the outer Verifier circuit: a Groth16 verifier for
// gnark BN254 or BLS12-381 proofs, checked with polyring's ring pairing (or,
// for comparison, gnark's own). v0.1 handles inner circuits that carry no
// BSB22 commitments of their own -- the poseidon demo's case.
package recursion

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/std/ring_bls12381"
	"github.com/mistcash/polyring/std/ring_bn254"
)

// G1Affine is a point on the inner curve, over its emulated base field F.
type G1Affine[F emulated.FieldParams] = sw_emulated.AffinePoint[F]

// pairing is the part of a pairing implementation the verifier uses: the ring
// pairing, or gnark's through [gnarkPairing].
type pairing[F emulated.FieldParams, G2El, GtEl any] interface {
	AssertIsOnG1(*G1Affine[F])
	PairingCheck(P []*G1Affine[F], Q []*G2El, previous *GtEl) error
}

// gnarkPairing adapts gnark's sw_bn254 / sw_bls12381 pairing to [pairing].
type gnarkPairing[F emulated.FieldParams, G2El, GtEl any] struct {
	p interface {
		AssertIsOnG1(*G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*G1Affine[F], []*G2El, *GtEl)
	}
}

func (g gnarkPairing[F, G2El, GtEl]) AssertIsOnG1(P *G1Affine[F]) { g.p.AssertIsOnG1(P) }
func (g gnarkPairing[F, G2El, GtEl]) PairingCheck(P []*G1Affine[F], Q []*G2El, previous *GtEl) error {
	g.p.AssertMultiMillerLoopAndFinalExpIsOne(P, Q, previous)
	return nil
}

// newPairing returns the ring pairing, or gnark's with useGnark, over the
// curve G2El belongs to.
func newPairing[F emulated.FieldParams, G2El, GtEl any](api frontend.API, useGnark bool) (pairing[F, G2El, GtEl], error) {
	var (
		p   any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		if useGnark {
			p, err = sw_bn254.NewPairing(api)
		} else {
			p, err = ring_bn254.NewPairing(api)
		}
	case *sw_bls12381.G2Affine:
		if useGnark {
			p, err = sw_bls12381.NewPairing(api)
		} else {
			p, err = ring_bls12381.NewPairing(api)
		}
	default:
		return nil, fmt.Errorf("unsupported G2 type %T", (*G2El)(nil))
	}
	if err != nil {
		return nil, err
	}
	if !useGnark {
		return p.(pairing[F, G2El, GtEl]), nil
	}
	return gnarkPairing[F, G2El, GtEl]{p: p.(interface {
		AssertIsOnG1(*G1Affine[F])
		AssertMultiMillerLoopAndFinalExpIsOne([]*G1Affine[F], []*G2El, *GtEl)
	})}, nil
}

// Verifier verifies Groth16 proofs against a fixed [VerifyingKey].
type Verifier[F, S emulated.FieldParams, G2El, GtEl any] struct {
	curve   *sw_emulated.Curve[F, S]
	pairing pairing[F, G2El, GtEl]
	vk      *vkConstants[F, G2El, GtEl]
}

// NewVerifier returns a verifier for proofs against vk, baking vk's points in
// as compile-time constants. The verifier checks pairings with the ring
// pairing unless [WithGnarkPairing] is given.
func NewVerifier[F, S emulated.FieldParams, G2El, GtEl any](api frontend.API, vk *VerifyingKey, opts ...Option) (*Verifier[F, S, G2El, GtEl], error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	consts, err := constantsOf[F, G2El, GtEl](vk)
	if err != nil {
		return nil, err
	}
	// the ring checker has to be registered before anything else creates an
	// emulated field, see ringpairing.New.
	pr, err := newPairing[F, G2El, GtEl](api, cfg.gnarkPairing)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	curve, err := sw_emulated.New[F, S](api, sw_emulated.GetCurveParams[F]())
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	return &Verifier[F, S, G2El, GtEl]{curve: curve, pairing: pr, vk: consts}, nil
}

// AssertProof asserts that proof is a valid Groth16 proof of the inner
// circuit's statement against publicWitness, under the verifier's fixed
// verifying key.
//
// The Groth16 pairing identity e(A,B)·e(α,β)⁻¹·e(L,γ)⁻¹·e(C,δ)⁻¹ = 1 is
// checked as a single pairing check -- the verifying key's α, γ and δ are
// already negated in [NewVerifyingKey], so the identity becomes a plain
// product-equals-one.
//
// Only the first term is a full pairing: A, B are the proof's. Everything
// else is fixed by the verifying key, so the identity costs one Miller loop
// over three G1 points rather than four in-circuit ladders:
//
//   - e(L,γ)⁻¹ and e(C,δ)⁻¹ are fixed-Q pairs. γ and δ never vary, so their
//     line evaluations are precomputed off-circuit and the ladder and the G2
//     subgroup check for them leave the circuit entirely.
//   - e(α,β)⁻¹ has both points fixed, so its Miller loop value is a
//     compile-time constant, folded into the product as the previous value.
//
// AssertProof itself has no notion of BSB22 commitments -- there is no
// Commitments field on [Proof] and no PoK check here. The "no commitments"
// restriction documented on [NewVerifyingKey] and [Circuit.Assign] holds only
// because their rejection of commitment keys/commitments keeps the key's K
// and the public witness matching what an inner circuit without commitments
// produces; it is not independently enforced below.
func (v *Verifier[F, S, G2El, GtEl]) AssertProof(proof Proof[F, G2El], publicWitness PublicWitness[S]) error {
	k := v.vk.k
	if len(publicWitness.Public) != len(k)-1 {
		return fmt.Errorf("invalid witness size, got %d, expected %d", len(publicWitness.Public), len(k)-1)
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
	kTerms := make([]*G1Affine[F], len(k)-1)
	for i := range kTerms {
		kTerms[i] = &k[i+1]
	}
	kScalars := make([]*emulated.Element[S], len(publicWitness.Public))
	for i := range publicWitness.Public {
		kScalars[i] = &publicWitness.Public[i]
	}
	kSum, err := v.curve.MultiScalarMul(kTerms, kScalars)
	if err != nil {
		return fmt.Errorf("k-sum multi scalar mul: %w", err)
	}
	kSum = v.curve.AddUnified(kSum, &k[0])

	// Bs gets no AssertIsOnG2: it carries no precomputed lines, so the
	// pairing check runs its ladder in-circuit, and both pairings assert the
	// point is on the twist and in G2 there, reusing the ladder endpoint.
	// A separate AssertIsOnG2 would repeat that at ~100k constraints.
	v.pairing.AssertIsOnG1(&proof.Ar)
	v.pairing.AssertIsOnG1(&proof.Krs)

	return v.pairing.PairingCheck(
		[]*G1Affine[F]{&proof.Ar, kSum, &proof.Krs},
		[]*G2El{&proof.Bs, &v.vk.gammaNeg, &v.vk.deltaNeg},
		&v.vk.alphaBeta,
	)
}
