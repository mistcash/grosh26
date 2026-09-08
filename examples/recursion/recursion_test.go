// Package recursion_test is the end-to-end example: a Groth16 proof of the
// poseidon preimage circuit in examples/poseidon, verified inside an outer
// circuit by std/recursion's Verifier.
//
// The outer check is the Groth16 pairing identity
//
//	e(A, B) · e(α,β)⁻¹ · e(L,γ)⁻¹ · e(C,δ)⁻¹ = 1
//
// assembled from one full pairing (e(A,B), both points from the witness)
// and three fixed-Q pairs (e(α,β)⁻¹, e(L,γ)⁻¹ and e(C,δ)⁻¹, whose G2 points
// come from the verifying key with their line evaluations precomputed
// off-circuit).
package recursion_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/examples/poseidon"
	"github.com/mistcash/grosh26/std/recursion"
)

// innerFixture compiles the poseidon inner circuit, runs its Groth16 setup
// and proves a genuine preimage.
type innerFixture struct {
	vk     *groth16backend.VerifyingKey
	proof  *groth16backend.Proof
	public fr.Vector
}

func newInnerFixture(t *testing.T) *innerFixture {
	t.Helper()
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poseidon.Circuit{})
	require.NoError(t, err)

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	require.NoError(t, err)

	assignment, err := poseidon.AssignRandom()
	require.NoError(t, err)
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, fullWitness)
	require.NoError(t, err)

	publicWitness, err := fullWitness.Public()
	require.NoError(t, err)
	require.NoError(t, groth16.Verify(innerProof, innerVK, publicWitness))

	bnVK, ok := innerVK.(*groth16backend.VerifyingKey)
	require.True(t, ok)
	bnProof, ok := innerProof.(*groth16backend.Proof)
	require.True(t, ok)
	vector, ok := publicWitness.Vector().(fr.Vector)
	require.True(t, ok)

	return &innerFixture{vk: bnVK, proof: bnProof, public: vector}
}

// circuit builds the outer circuit and its witness from native values, so
// subtests can tamper with the proof or public inputs first.
func (fx *innerFixture) circuit(t *testing.T, vk *groth16backend.VerifyingKey, proof *groth16backend.Proof, public fr.Vector) (*recursion.Circuit, *recursion.Circuit) {
	t.Helper()
	outerVK, err := recursion.NewVerifyingKey(vk)
	require.NoError(t, err)
	circuitProof, err := recursion.ValueOfProof(proof)
	require.NoError(t, err)

	unassigned := recursion.NewCircuit(outerVK)
	assignment := &recursion.Circuit{
		Proof:         circuitProof,
		PublicWitness: recursion.ValueOfPublicWitness(public),
	}
	return unassigned, assignment
}

func TestGroth16Verifier(t *testing.T) {
	fx := newInnerFixture(t)
	assert := test.NewAssert(t)

	t.Run("solved", func(t *testing.T) {
		unassigned, assignment := fx.circuit(t, fx.vk, fx.proof, fx.public)
		assert.NoError(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
	})

	t.Run("rejects tampered proof", func(t *testing.T) {
		tampered := *fx.proof
		_, _, g1, _ := bn254.Generators()
		tampered.Ar.ScalarMultiplication(&g1, big.NewInt(42))

		unassigned, assignment := fx.circuit(t, fx.vk, &tampered, fx.public)
		assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
	})

	// The C point pairs against δ, which is fixed by the verifying key, so
	// this is the fixed-Q path's non-vacuity check.
	t.Run("rejects tampered fixed-Q term", func(t *testing.T) {
		tampered := *fx.proof
		_, _, g1, _ := bn254.Generators()
		tampered.Krs.ScalarMultiplication(&g1, big.NewInt(42))

		unassigned, assignment := fx.circuit(t, fx.vk, &tampered, fx.public)
		assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
	})

	t.Run("rejects wrong public input", func(t *testing.T) {
		wrong := make(fr.Vector, len(fx.public))
		copy(wrong, fx.public)
		wrong[0].Add(&wrong[0], new(fr.Element).SetOne())

		unassigned, assignment := fx.circuit(t, fx.vk, fx.proof, wrong)
		assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
	})

	// β, γ and δ skip the in-circuit ladder, so nothing downstream would
	// catch a malformed key point: NewG2AffineFixed panics when the pairs
	// are built, like gnark (surfaced as an error by test.IsSolved).
	t.Run("rejects malformed verifying key", func(t *testing.T) {
		offTwist := func(p bn254.G2Affine) bn254.G2Affine {
			p.X.A0.Add(&p.X.A0, new(fp.Element).SetOne())
			return p
		}

		for name, tamper := range map[string]func(*groth16backend.VerifyingKey){
			"beta":  func(vk *groth16backend.VerifyingKey) { vk.G2.Beta = offTwist(vk.G2.Beta) },
			"gamma": func(vk *groth16backend.VerifyingKey) { vk.G2.Gamma = offTwist(vk.G2.Gamma) },
			"delta": func(vk *groth16backend.VerifyingKey) { vk.G2.Delta = offTwist(vk.G2.Delta) },
		} {
			t.Run(name, func(t *testing.T) {
				broken := *fx.vk
				tamper(&broken)

				outerVK, err := recursion.NewVerifyingKey(&broken)
				require.NoError(t, err)
				circuitProof, err := recursion.ValueOfProof(fx.proof)
				require.NoError(t, err)
				assignment := &recursion.Circuit{
					Proof:         circuitProof,
					PublicWitness: recursion.ValueOfPublicWitness(fx.public),
				}
				err = test.IsSolved(recursion.NewCircuit(outerVK), assignment, ecc.BN254.ScalarField())
				assert.Error(err)
				assert.Contains(err.Error(), "not in the G2 subgroup")
			})
		}
	})
}
