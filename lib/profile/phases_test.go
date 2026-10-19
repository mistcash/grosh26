package profile

// Per-phase constraint breakdown of the outer verifier circuit. The phases of
// AssertProof are measured by compiling small circuits that each isolate one
// of them, so std/recursion stays the only verifier: kSum, the G1 and G2
// checks and the Bs ladder are measured directly, and whatever they do not
// account for is the rest of the pairing check.

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/polyring/lib/gnarkpairing"
	"github.com/mistcash/polyring/std/recursion"
	"github.com/mistcash/polyring/std/ring_bls12381"
	"github.com/mistcash/polyring/std/ring_bn254"
)

// G1Affine is a point on the inner curve, over its emulated base field F.
type G1Affine[F emulated.FieldParams] = recursion.G1Affine[F]

// newPairing returns gnark's pairing or the ring pairing over G2El's curve.
// Call it before anything else in Define creates an emulated field: the ring
// pairing registers a deferred check, see ringpairing.New.
func newPairing[F emulated.FieldParams, G2El, GtEl any](api frontend.API, useGnark bool) (recursion.Pairing[F, G2El, GtEl], error) {
	if useGnark {
		return gnarkpairing.NewPairing[F, G2El, GtEl](api)
	}
	var (
		p   any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		p, err = ring_bn254.NewPairing(api)
	case *sw_bls12381.G2Affine:
		p, err = ring_bls12381.NewPairing(api)
	default:
		return nil, fmt.Errorf("unsupported G2 type %T", (*G2El)(nil))
	}
	if err != nil {
		return nil, err
	}
	return p.(recursion.Pairing[F, G2El, GtEl]), nil
}

// keyConstants are the inner key's points as in-circuit constants, in the
// shapes the verifier bakes in: K in G1, β, γ and δ carrying precomputed
// lines and e(α,β) as a Miller loop value. The isolating circuits only need
// the right shapes -- counts do not depend on the values -- so the points
// are not negated as the verifier's are.
type keyConstants[F emulated.FieldParams, G2El, GtEl any] struct {
	k                  []G1Affine[F]
	beta, gamma, delta G2El
	alphaBeta          GtEl
}

// constantsOf builds vk's [keyConstants]. Emulated constants cache circuit
// state once used, so call it inside Define.
func constantsOf[F emulated.FieldParams, G2El, GtEl any](vk groth16.VerifyingKey) (*keyConstants[F, G2El, GtEl], error) {
	var c any
	switch vk := vk.(type) {
	case *groth16bn254.VerifyingKey:
		ml, err := bn254.MillerLoopFixedQ(
			[]bn254.G1Affine{vk.G1.Alpha},
			[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(vk.G2.Beta)},
		)
		if err != nil {
			return nil, err
		}
		k := make([]G1Affine[emparams.BN254Fp], len(vk.G1.K))
		for i := range k {
			k[i] = sw_bn254.NewG1Affine(vk.G1.K[i])
		}
		c = &keyConstants[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl]{
			k:         k,
			beta:      sw_bn254.NewG2AffineFixed(vk.G2.Beta),
			gamma:     sw_bn254.NewG2AffineFixed(vk.G2.Gamma),
			delta:     sw_bn254.NewG2AffineFixed(vk.G2.Delta),
			alphaBeta: sw_bn254.NewGTEl(ml),
		}
	case *groth16bls12381.VerifyingKey:
		ml, err := bls12381.MillerLoopFixedQ(
			[]bls12381.G1Affine{vk.G1.Alpha},
			[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{bls12381.PrecomputeLines(vk.G2.Beta)},
		)
		if err != nil {
			return nil, err
		}
		k := make([]G1Affine[emparams.BLS12381Fp], len(vk.G1.K))
		for i := range k {
			k[i] = sw_bls12381.NewG1Affine(vk.G1.K[i])
		}
		c = &keyConstants[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
			k:         k,
			beta:      sw_bls12381.NewG2AffineFixed(vk.G2.Beta),
			gamma:     sw_bls12381.NewG2AffineFixed(vk.G2.Gamma),
			delta:     sw_bls12381.NewG2AffineFixed(vk.G2.Delta),
			alphaBeta: sw_bls12381.NewGTEl(ml),
		}
	}
	kc, ok := c.(*keyConstants[F, G2El, GtEl])
	if !ok {
		return nil, fmt.Errorf("verifying key %T is not for G2 type %T", vk, (*G2El)(nil))
	}
	return kc, nil
}

// kSumCircuit isolates the K-sum recombination k[0] + Σ k[i+1]·public[i],
// run the verifier's way: MultiScalarMul over the constant k[i+1], then
// AddUnified with k[0]. Both pairings run it, so it is measured once. No
// terminal assert: emulated ops emit constraints eagerly, so the bare Define
// counts exactly the recombination.
type kSumCircuit[F, S emulated.FieldParams, G2El, GtEl any] struct {
	Public []emulated.Element[S]

	vk groth16.VerifyingKey
}

func (c *kSumCircuit[F, S, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := sw_emulated.New[F, S](api, sw_emulated.GetCurveParams[F]())
	if err != nil {
		return err
	}
	consts, err := constantsOf[F, G2El, GtEl](c.vk)
	if err != nil {
		return err
	}
	k := consts.k
	if len(c.Public) != len(k)-1 {
		return fmt.Errorf("got %d public inputs, key expects %d", len(c.Public), len(k)-1)
	}
	terms := make([]*G1Affine[F], len(c.Public))
	scalars := make([]*emulated.Element[S], len(c.Public))
	for i := range c.Public {
		terms[i], scalars[i] = &k[i+1], &c.Public[i]
	}
	kSum, err := curve.MultiScalarMul(terms, scalars)
	if err != nil {
		return err
	}
	_ = curve.AddUnified(kSum, &k[0])
	return nil
}

// g1ChecksCircuit isolates the two AssertIsOnG1, on Ar and Krs.
type g1ChecksCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	Ar, Krs G1Affine[F]

	gnark bool
}

func (c *g1ChecksCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api, c.gnark)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.Ar)
	pr.AssertIsOnG1(&c.Krs)
	return nil
}

// pairingCheckCircuit isolates the pairing check over (Ar,Bs), (kSum,γ),
// (Krs,δ) with e(α,β) as the previous value. With fixedBs, Bs is swapped for
// the constant β carrying precomputed lines, which drops the in-circuit
// ladder: the difference between the two is the Bs ladder, including the
// on-twist check and the subgroup check reusing the ladder endpoint.
type pairingCheckCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	Ar, KSum, Krs G1Affine[F]
	Bs            G2El

	vk             groth16.VerifyingKey
	gnark, fixedBs bool
}

func (c *pairingCheckCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api, c.gnark)
	if err != nil {
		return err
	}
	consts, err := constantsOf[F, G2El, GtEl](c.vk)
	if err != nil {
		return err
	}
	bs := &c.Bs
	if c.fixedBs {
		bs = &consts.beta
	}
	return pr.PairingCheck(
		[]*G1Affine[F]{&c.Ar, &c.KSum, &c.Krs},
		[]*G2El{bs, &consts.gamma, &consts.delta},
		&consts.alphaBeta,
	)
}

// phases is one pairing's constraint count per verifier phase.
type phases struct {
	total, kSum, g1Checks, ladder, rest int
}

// logPhases prints the per-phase constraint breakdown of the outer verifier
// for innerVK, gnark's pairing against the ring pairing. The phases sum to
// the verifier's total by construction: "loop+tail+previous" -- the Miller
// accumulation, the final exponentiation or residue tail and the folded-in
// e(α,β) -- is whatever the measured phases do not account for. Isolating it
// standalone would change the computation (seeding, batching).
func logPhases[F, S emulated.FieldParams, G2El, GtEl any](b *testing.B, name string, innerVK groth16.VerifyingKey, vk *recursion.VerifyingKey) {
	b.Helper()
	count := func(c frontend.Circuit) int {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			b.Fatal(err)
		}
		return ccs.GetNbConstraints()
	}
	kSum := count(&kSumCircuit[F, S, G2El, GtEl]{Public: make([]emulated.Element[S], innerVK.NbPublicWitness()), vk: innerVK})
	measure := func(gnark bool) phases {
		var outer frontend.Circuit = recursion.NewCircuit[F, S, G2El, GtEl](vk)
		if gnark {
			outer = gnarkpairing.NewCircuit[F, S, G2El, GtEl](vk)
		}
		p := phases{
			total:    count(outer),
			kSum:     kSum,
			g1Checks: count(&g1ChecksCircuit[F, G2El, GtEl]{gnark: gnark}),
		}
		check := count(&pairingCheckCircuit[F, G2El, GtEl]{vk: innerVK, gnark: gnark})
		p.ladder = check - count(&pairingCheckCircuit[F, G2El, GtEl]{vk: innerVK, gnark: gnark, fixedBs: true})
		p.rest = p.total - p.kSum - p.g1Checks - p.ladder
		return p
	}
	gnark, ring := measure(true), measure(false)

	b.Logf("constraint profile (r1cs, inner %s):", name)
	b.Logf("%-22s %10s %10s %10s", "phase", "gnark", "polyring", "delta")
	for _, row := range []struct {
		phase string
		g, r  int
	}{
		{"total", gnark.total, ring.total},
		{"kSum recomb (shared)", gnark.kSum, ring.kSum},
		{"G1 checks x2", gnark.g1Checks, ring.g1Checks},
		{"Bs ladder+subgroup", gnark.ladder, ring.ladder},
		{"loop+tail+previous", gnark.rest, ring.rest},
	} {
		b.Logf("%-22s %10d %10d %10d", row.phase, row.g, row.r, row.g-row.r)
	}
}
