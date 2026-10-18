// Package recursion_test is the end-to-end example: a Groth16 proof of the
// poseidon preimage circuit in examples/poseidon, over BN254 or BLS12-381,
// verified inside a BN254 outer circuit by std/recursion's Verifier.
//
// The outer check is the Groth16 pairing identity
//
//	e(A, B) · e(α,β)⁻¹ · e(L,γ)⁻¹ · e(C,δ)⁻¹ = 1
//
// assembled from one full pairing (e(A,B), both points from the witness)
// and three fixed pairs (e(α,β)⁻¹, e(L,γ)⁻¹ and e(C,δ)⁻¹, whose G2 points
// come from the verifying key with their line evaluations precomputed
// off-circuit).
package recursion_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/polyring/examples/poseidon"
	"github.com/mistcash/polyring/std/recursion"
)

func TestGroth16Verifier(t *testing.T) {
	t.Run("bn254", testGroth16Verifier[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl])
	t.Run("bls12-381", testGroth16Verifier[emparams.BLS12381Fp, emparams.BLS12381Fr, sw_bls12381.G2Affine, sw_bls12381.GTEl])
}

func testGroth16Verifier[F, S emulated.FieldParams, G2El, GtEl any](t *testing.T) {
	curve := ecc.BN254
	if _, ok := any((*G2El)(nil)).(*sw_bls12381.G2Affine); ok {
		curve = ecc.BLS12_381
	}
	innerVK, proof, public, err := poseidon.Prove(curve)
	require.NoError(t, err)
	vk, err := recursion.NewVerifyingKey(innerVK)
	require.NoError(t, err)
	outerField := ecc.BN254.ScalarField()

	assign := func(t *testing.T, proof groth16.Proof) *recursion.Circuit[F, S, G2El, GtEl] {
		assignment := recursion.NewCircuit[F, S, G2El, GtEl](vk)
		require.NoError(t, assignment.Assign(proof, public))
		return assignment
	}
	unassigned := func() *recursion.Circuit[F, S, G2El, GtEl] { return recursion.NewCircuit[F, S, G2El, GtEl](vk) }

	t.Run("solved", func(t *testing.T) {
		test.NewAssert(t).NoError(test.IsSolved(unassigned(), assign(t, proof), outerField))
	})

	t.Run("rejects tampered proof", func(t *testing.T) {
		tampered := tamperProof(proof, func(ar, _ any) {
			setG1(ar, 42)
		})
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, tampered), outerField))
	})

	// The C point pairs against δ, which is fixed by the verifying key, so
	// this is the fixed-Q path's non-vacuity check.
	t.Run("rejects tampered fixed-Q term", func(t *testing.T) {
		tampered := tamperProof(proof, func(_, krs any) {
			setG1(krs, 42)
		})
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, tampered), outerField))
	})

	// Bs is the one G2 point the circuit receives as a witness: the pairing
	// check's ladder is the only thing asserting it is on the twist and in
	// G2, there being no separate AssertIsOnG2.
	t.Run("rejects Bs off the twist", func(t *testing.T) {
		tampered := tamperBs(t, proof, false)
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, tampered), outerField))
	})

	t.Run("rejects Bs outside the G2 subgroup", func(t *testing.T) {
		tampered := tamperBs(t, proof, true)
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, tampered), outerField))
	})

	t.Run("rejects wrong public input", func(t *testing.T) {
		assignment := assign(t, proof)
		assignment.PublicWitness.Public[0] = emulated.ValueOf[S](12345)
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assignment, outerField))
	})

	// β, γ and δ skip the in-circuit ladder, so nothing downstream would
	// catch a malformed key point: NewVerifyingKey refuses it up front.
	t.Run("rejects malformed verifying key", func(t *testing.T) {
		for _, name := range []string{"beta", "gamma", "delta"} {
			t.Run(name, func(t *testing.T) {
				_, err := recursion.NewVerifyingKey(tamperVK(innerVK, name))
				require.Error(t, err)
				require.Contains(t, err.Error(), name+" point is not in the G2 subgroup")
			})
		}
	})
}

// tamperProof returns a copy of proof with f applied to pointers to its Ar
// and Krs points.
func tamperProof(proof groth16.Proof, f func(ar, krs any)) groth16.Proof {
	switch p := proof.(type) {
	case *groth16bn254.Proof:
		c := *p
		f(&c.Ar, &c.Krs)
		return &c
	case *groth16bls12381.Proof:
		c := *p
		f(&c.Ar, &c.Krs)
		return &c
	}
	panic("unsupported proof")
}

// tamperBs returns a copy of proof with Bs replaced by a point that is not in
// G2: off the twist, or with outside set on the twist but outside the
// prime-order subgroup.
func tamperBs(t testing.TB, proof groth16.Proof, outside bool) groth16.Proof {
	switch p := proof.(type) {
	case *groth16bn254.Proof:
		c := *p
		if outside {
			c.Bs = bnTwistPointOutsideG2(t)
		} else {
			c.Bs.X.A0.Add(&c.Bs.X.A0, new(bnfp.Element).SetOne())
		}
		return &c
	case *groth16bls12381.Proof:
		c := *p
		if outside {
			c.Bs = blsTwistPointOutsideG2(t)
		} else {
			c.Bs.X.A0.Add(&c.Bs.X.A0, new(blsfp.Element).SetOne())
		}
		return &c
	}
	panic("unsupported proof")
}

// bnTwistPointOutsideG2 returns a point on the twist y² = x³ + b' that is not in
// the prime-order subgroup: the twist's cofactor is huge, so a random point
// on it is outside G2 but for a negligible chance. b' = y² - x³ comes from the
// G2 generator.
func bnTwistPointOutsideG2(t testing.TB) bn254.G2Affine {
	t.Helper()
	_, _, _, g2 := bn254.Generators()
	var b, x3 bn254.E2
	b.Square(&g2.Y)
	x3.Square(&g2.X).Mul(&x3, &g2.X)
	b.Sub(&b, &x3)

	for range 100 {
		var p bn254.G2Affine
		_, err := p.X.SetRandom()
		require.NoError(t, err)
		var rhs bn254.E2
		rhs.Square(&p.X).Mul(&rhs, &p.X).Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		p.Y.Sqrt(&rhs)
		require.True(t, p.IsOnCurve())
		require.False(t, p.IsInSubGroup())
		return p
	}
	t.Fatal("no twist point outside G2 found")
	return bn254.G2Affine{}
}

// blsTwistPointOutsideG2 is [bnTwistPointOutsideG2] for BLS12-381.
func blsTwistPointOutsideG2(t testing.TB) bls12381.G2Affine {
	t.Helper()
	_, _, _, g2 := bls12381.Generators()
	var b, x3 bls12381.E2
	b.Square(&g2.Y)
	x3.Square(&g2.X).Mul(&x3, &g2.X)
	b.Sub(&b, &x3)

	for range 100 {
		var p bls12381.G2Affine
		_, err := p.X.SetRandom()
		require.NoError(t, err)
		var rhs bls12381.E2
		rhs.Square(&p.X).Mul(&rhs, &p.X).Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		p.Y.Sqrt(&rhs)
		require.True(t, p.IsOnCurve())
		require.False(t, p.IsInSubGroup())
		return p
	}
	t.Fatal("no twist point outside G2 found")
	return bls12381.G2Affine{}
}

// setG1 sets a native G1 point to [k]G1.
func setG1(p any, k int64) {
	switch p := p.(type) {
	case *bn254.G1Affine:
		_, _, g1, _ := bn254.Generators()
		p.ScalarMultiplication(&g1, big.NewInt(k))
	case *bls12381.G1Affine:
		_, _, g1, _ := bls12381.Generators()
		p.ScalarMultiplication(&g1, big.NewInt(k))
	}
}

// tamperVK returns a copy of vk with the named G2 point moved off the twist.
func tamperVK(vk groth16.VerifyingKey, name string) groth16.VerifyingKey {
	switch vk := vk.(type) {
	case *groth16bn254.VerifyingKey:
		c := *vk
		pt := map[string]*bn254.G2Affine{"beta": &c.G2.Beta, "gamma": &c.G2.Gamma, "delta": &c.G2.Delta}[name]
		pt.X.A0.Add(&pt.X.A0, new(bnfp.Element).SetOne())
		return &c
	case *groth16bls12381.VerifyingKey:
		c := *vk
		pt := map[string]*bls12381.G2Affine{"beta": &c.G2.Beta, "gamma": &c.G2.Gamma, "delta": &c.G2.Delta}[name]
		pt.X.A0.Add(&pt.X.A0, new(blsfp.Element).SetOne())
		return &c
	}
	panic("unsupported verifying key")
}
