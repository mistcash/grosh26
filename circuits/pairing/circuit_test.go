package pairing_test

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/circuits/pairing"
	"github.com/mistcash/grosh26/internal/soltest"
	"github.com/mistcash/grosh26/internal/timing"
	"github.com/mistcash/grosh26/solidity"
)

// nbPublicInputs is the size of the input array the generated verifier takes:
// P1 and P2, two coordinates each, four limbs per coordinate.
const nbPublicInputs = 16

func TestCircuitSolved(t *testing.T) {
	assert := test.NewAssert(t)

	assignment, err := pairing.AssignRandom()
	assert.NoError(err)
	assert.NoError(test.IsSolved(&pairing.Circuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestCircuitRejectsNonPairing makes sure the check is not vacuous: swapping P2
// for an unrelated point breaks e(P1,Q1)·e(P2,Q2) == 1.
func TestCircuitRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b fr.Element
	_, err := a.SetRandom()
	assert.NoError(err)
	_, err = b.SetRandom()
	assert.NoError(err)

	assignment := pairing.Assign(&a, &b)
	_, _, g1, _ := bn254.Generators()
	var wrong bn254.G1Affine
	wrong.ScalarMultiplication(&g1, big.NewInt(42))
	assignment.P2 = sw_bn254.NewG1Affine(wrong)

	assert.Error(test.IsSolved(&pairing.Circuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestOnChain is the whole pipeline: compile the ring pairing circuit, set it
// up and prove it with gnark, generate the verifier with our generator, and run
// the proof against it on a real EVM. Along the way it logs the circuit's R1CS
// and SCS constraint counts, the pipeline timings and the on-chain gas. The
// setup dominates, so it is skipped under -short.
func TestOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the full pairing circuit setup under -short")
	}
	solcPath := soltest.Solc(t)

	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairing.Circuit{})
	require.NoError(t, err)
	t.Logf("r1cs compiled in %s: %d constraints, %d public inputs, %d secret wires, %d coefficients",
		timing.Since(start), ccs.GetNbConstraints(), ccs.GetNbPublicVariables(),
		ccs.GetNbSecretVariables(), ccs.GetNbCoefficients())

	// the same circuit over the plonk-ish builder, for comparison
	start = time.Now()
	scsCcs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &pairing.Circuit{})
	require.NoError(t, err)
	t.Logf("scs compiled in %s: %d constraints, %d public inputs, %d secret wires, %d coefficients",
		timing.Since(start), scsCcs.GetNbConstraints(), scsCcs.GetNbPublicVariables()-1,
		scsCcs.GetNbSecretVariables(), scsCcs.GetNbCoefficients())

	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)
	t.Logf("groth16 setup in %s", timing.Since(start))

	assignment, err := pairing.AssignRandom()
	require.NoError(t, err)
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err := fullWitness.Public()
	require.NoError(t, err)

	start = time.Now()
	proof, err := groth16.Prove(ccs, pk, fullWitness, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	t.Logf("groth16 prove in %s", timing.Since(start))

	start = time.Now()
	require.NoError(t, groth16.Verify(proof, vk, publicWitness, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))
	t.Logf("groth16 verify in %s", timing.Since(start))

	bnVK, ok := vk.(*groth16bn254.VerifyingKey)
	require.True(t, ok)
	bnProof, ok := proof.(*groth16bn254.Proof)
	require.True(t, ok)
	// two for the polynomial ring checks, one for the range checker
	require.Len(t, bnProof.Commitments, 3)

	var src bytes.Buffer
	require.NoError(t, solidity.ExportSolidity(bnVK, &src))
	deployment := soltest.Deploy(t, solcPath, src.String())
	contract := deployment.Contract

	vector, ok := publicWitness.Vector().(fr.Vector)
	require.True(t, ok)
	require.Len(t, vector, nbPublicInputs)

	var publicInputs [nbPublicInputs]*big.Int
	for i := range vector {
		publicInputs[i] = new(big.Int)
		vector[i].BigInt(publicInputs[i])
	}
	proofBytes := solidity.MarshalSolidity(bnProof)
	t.Logf("proof: %d bytes, %d public inputs", len(proofBytes), len(publicInputs))

	var results []any
	require.NoError(t,
		contract.Call(&bind.CallOpts{}, &results, "verifyProof", proofBytes, publicInputs),
		"a genuine proof must verify on-chain")

	receipt := deployment.Send(t, "verifyProof", proofBytes, publicInputs)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	t.Logf("verifyProof: %d gas", receipt.GasUsed)

	tampered := publicInputs
	tampered[0] = new(big.Int).Add(publicInputs[0], big.NewInt(1))
	var out []any
	require.Error(t,
		contract.Call(&bind.CallOpts{}, &out, "verifyProof", proofBytes, tampered),
		"a proof for different public inputs must be rejected on-chain")
}
