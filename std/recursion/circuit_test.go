package recursion_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/circuits/poseidon"
	"github.com/mistcash/grosh26/std/recursion"
)

// innerFixture compiles the poseidon inner circuit, runs its Groth16 setup
// and proves a genuine preimage, keeping both the native and outer-circuit
// forms so tests can tamper at the native level before converting -- the same
// pattern circuits/pairing/circuit_test.go uses.
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

// circuit builds the outer Circuit and its witness from the fixture's native
// forms, letting the caller tamper with proof/public before calling.
func (fx *innerFixture) circuit(t *testing.T, proof *groth16backend.Proof, public fr.Vector) (*recursion.Circuit, *recursion.Circuit) {
	t.Helper()
	vk, err := recursion.NewVerifyingKey(fx.vk)
	require.NoError(t, err)
	circuitProof, err := recursion.ValueOfProof(proof)
	require.NoError(t, err)

	unassigned := recursion.NewCircuit(vk)
	assignment := &recursion.Circuit{
		Proof:         circuitProof,
		PublicWitness: recursion.ValueOfPublicWitness(public),
	}
	return unassigned, assignment
}

func TestOuterCircuitSolved(t *testing.T) {
	fx := newInnerFixture(t)
	assert := test.NewAssert(t)

	unassigned, assignment := fx.circuit(t, fx.proof, fx.public)
	assert.NoError(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
}

// TestOuterCircuitRejectsTamperedProof makes sure the check is not vacuous:
// swapping a proof point for an unrelated one breaks verification.
func TestOuterCircuitRejectsTamperedProof(t *testing.T) {
	fx := newInnerFixture(t)
	assert := test.NewAssert(t)

	tampered := *fx.proof
	_, _, g1, _ := bn254.Generators()
	tampered.Ar.ScalarMultiplication(&g1, big.NewInt(42))

	unassigned, assignment := fx.circuit(t, &tampered, fx.public)
	assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
}

// TestOuterCircuitRejectsWrongPublicInput makes sure a genuine proof does not
// verify against public inputs it was not generated for.
func TestOuterCircuitRejectsWrongPublicInput(t *testing.T) {
	fx := newInnerFixture(t)
	assert := test.NewAssert(t)

	wrong := make(fr.Vector, len(fx.public))
	copy(wrong, fx.public)
	wrong[0].Add(&wrong[0], new(fr.Element).SetOne())

	unassigned, assignment := fx.circuit(t, fx.proof, wrong)
	assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
}

// TestOuterCircuitNonVacuous proves a second, independent poseidon proof and
// checks it does not verify against the first fixture's public input: the
// outer circuit must bind a proof to the specific public input it attests to,
// not merely accept any well-formed proof of the inner circuit.
func TestOuterCircuitNonVacuous(t *testing.T) {
	fx1 := newInnerFixture(t)
	fx2 := newInnerFixture(t)
	assert := test.NewAssert(t)

	unassigned, assignment := fx1.circuit(t, fx2.proof, fx1.public)
	assert.Error(test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField()))
}
