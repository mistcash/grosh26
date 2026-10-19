// Package recursion_test is the end-to-end example: a Groth16 proof of the
// MiMC preimage circuit in examples/mimc, over BN254 or BLS12-381,
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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/polyring/examples/mimc"
	"github.com/mistcash/polyring/std/recursion"
)

// attacks is what a curve's test file supplies to the shared scenarios: the
// inner curve and its ways of corrupting a proof or verifying key, which
// need the curve's concrete gnark types.
type attacks struct {
	curve ecc.ID
	// withAr and withKrs return a copy of the proof with that G1 point
	// replaced by a different valid one
	withAr, withKrs func(groth16.Proof) groth16.Proof
	// withBsOffTwist and withBsOutsideG2 return a copy of the proof with Bs
	// moved off the twist, or onto it but outside the prime-order subgroup
	withBsOffTwist, withBsOutsideG2 func(testing.TB, groth16.Proof) groth16.Proof
	// withVKOffTwist returns a copy of the key with the named G2 point
	// ("beta", "gamma" or "delta") moved off the twist
	withVKOffTwist func(groth16.VerifyingKey, string) groth16.VerifyingKey
}

func testGroth16Verifier[F, S emulated.FieldParams, G2El, GtEl any](t *testing.T, a attacks) {
	innerVK, proof, public, err := mimc.Prove(a.curve)
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
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, a.withAr(proof)), outerField))
	})

	// The C point pairs against δ, which is fixed by the verifying key, so
	// this is the fixed-Q path's non-vacuity check.
	t.Run("rejects tampered fixed-Q term", func(t *testing.T) {
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, a.withKrs(proof)), outerField))
	})

	// Bs is the one G2 point the circuit receives as a witness: the pairing
	// check's ladder is the only thing asserting it is on the twist and in
	// G2, there being no separate AssertIsOnG2.
	t.Run("rejects Bs off the twist", func(t *testing.T) {
		tampered := a.withBsOffTwist(t, proof)
		test.NewAssert(t).Error(test.IsSolved(unassigned(), assign(t, tampered), outerField))
	})

	t.Run("rejects Bs outside the G2 subgroup", func(t *testing.T) {
		tampered := a.withBsOutsideG2(t, proof)
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
				_, err := recursion.NewVerifyingKey(a.withVKOffTwist(innerVK, name))
				require.Error(t, err)
				require.Contains(t, err.Error(), name+" point is not in the G2 subgroup")
			})
		}
	})
}
