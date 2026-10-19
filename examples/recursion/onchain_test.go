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
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/polyring/examples/mimc"
	"github.com/mistcash/polyring/lib/gnarkpairing"
	"github.com/mistcash/polyring/lib/solidity"
	"github.com/mistcash/polyring/lib/soltest"
	"github.com/mistcash/polyring/std/recursion"
)

// TestOuterOnChain proves the outer recursive proof for real, generates its
// Solidity verifier with the multi-commitment generator, and runs it against
// a simulated EVM: the genuine proof verifies, every tampered commitment is
// caught, and a proof for different public inputs is rejected.
//
// It runs the same flow over gnark's in-circuit pairing as well, the
// baseline polyring is measured against: the same circuit and the same
// statement, differing only in the pairing check. The difference in the
// numbers it reports is the cost of the ring pairing -- a cheaper prover for
// a bigger on-chain verifier.
//
// Compiling, setting up and proving the outer circuit dominates, so it is
// skipped under -short like the repo's other on-chain tests.
func TestOuterOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the full outer circuit setup under -short")
	}
	solcPath := soltest.Solc(t)

	innerVK, innerProof, innerPublic, err := mimc.Prove(ecc.BN254)
	require.NoError(t, err)
	vk, err := recursion.NewVerifyingKey(innerVK)
	require.NoError(t, err)

	// cost is what one outer verifier costs on chain.
	type cost struct {
		name         string
		constraints  int
		commitments  int
		proofBytes   int
		contractSize int
		gas          uint64
	}
	costs := make([]cost, 0, 2)

	for _, variant := range []struct {
		name string
		// newCircuit builds the outer circuit; it has to be a fresh value
		// every time, since the pairing caches circuit state in Define.
		newCircuit func() frontend.Circuit
	}{
		{"gnark", func() frontend.Circuit {
			return gnarkpairing.NewCircuit[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		}},
		{"polyring", func() frontend.Circuit {
			return recursion.NewBN254Circuit(vk)
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			assignment := recursion.NewBN254Circuit(vk)
			require.NoError(t, assignment.Assign(innerProof, innerPublic))

			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, variant.newCircuit())
			require.NoError(t, err)
			pk, outerVK, err := groth16.Setup(ccs)
			require.NoError(t, err)

			full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			require.NoError(t, err)
			public, err := full.Public()
			require.NoError(t, err)

			proof, err := groth16.Prove(ccs, pk, full, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
			require.NoError(t, err)
			require.NoError(t, groth16.Verify(proof, outerVK, public, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))

			bnVK, ok := outerVK.(*groth16bn254.VerifyingKey)
			require.True(t, ok)
			bnProof, ok := proof.(*groth16bn254.Proof)
			require.True(t, ok)

			var src bytes.Buffer
			require.NoError(t, solidity.ExportSolidity(bnVK, &src))
			deployment := soltest.Deploy(t, solcPath, src.String())
			contract := deployment.Contract

			publicInputs := calldataInputs(t, bnVK, public)
			proofBytes := solidity.MarshalSolidity(bnProof)

			var results []any
			require.NoError(t,
				contract.Call(&bind.CallOpts{}, &results, "verifyProof", proofBytes, publicInputs),
				"a genuine outer proof must verify on-chain")

			receipt := deployment.Send(t, "verifyProof", proofBytes, publicInputs)
			require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
			t.Logf("verifyProof: %d gas (outer proof, %d commitments)", receipt.GasUsed, len(bnProof.Commitments))

			costs = append(costs, cost{
				name:         variant.name,
				constraints:  ccs.GetNbConstraints(),
				commitments:  len(bnProof.Commitments),
				proofBytes:   len(proofBytes),
				contractSize: deployment.BytecodeSize,
				gas:          receipt.GasUsed,
			})

			if variant.name != "polyring" {
				// the gnark baseline draws one commitment, so there is
				// nothing to tamper with beyond the proof itself.
				return
			}

			require.Len(t, bnProof.Commitments, 3, "the outer proof carries the ring checks' two commitments plus the range checker's")

			// tampering with any one of the three commitments must be caught:
			// the folding challenge binds all of them, not just the first.
			// Matches the struct-mutation pattern in lib/solidity's
			// TestThreeCommitmentsOnChain, immune to MarshalSolidity's
			// layout changing.
			for i := range bnProof.Commitments {
				t.Run(fmt.Sprintf("TamperCommitment%d", i), func(t *testing.T) {
					tampered := *bnProof
					tampered.Commitments = append([]bn254.G1Affine{}, bnProof.Commitments...)

					var s fr.Element
					_, err := s.SetRandom()
					require.NoError(t, err)
					var sBig big.Int
					s.BigInt(&sBig)
					tampered.Commitments[i].ScalarMultiplicationBase(&sBig)

					var out []any
					require.Errorf(t,
						contract.Call(&bind.CallOpts{}, &out, "verifyProof", solidity.MarshalSolidity(&tampered), publicInputs),
						"tampering with commitments[%d] must be rejected on-chain", i)
				})
			}

			wrongInputs := make([]*big.Int, len(publicInputs))
			copy(wrongInputs, publicInputs)
			wrongInputs[0] = new(big.Int).Add(publicInputs[0], big.NewInt(1))
			var out []any
			require.Error(t,
				contract.Call(&bind.CallOpts{}, &out, "verifyProof", proofBytes, wrongInputs),
				"a proof for different public inputs must be rejected on-chain")
		})
	}

	t.Log("on-chain cost of the outer verifier (BN254 inner proof, simulated EVM):")
	t.Logf("| %-24s | %12s | %12s |", "metric", "gnark", "polyring")
	for _, metric := range []struct {
		name string
		get  func(cost) string
	}{
		{"R1CS constraints", func(c cost) string { return fmt.Sprintf("%d", c.constraints) }},
		{"BSB22 commitments", func(c cost) string { return fmt.Sprintf("%d", c.commitments) }},
		{"proof size (bytes)", func(c cost) string { return fmt.Sprintf("%d", c.proofBytes) }},
		{"contract size (bytes)", func(c cost) string { return fmt.Sprintf("%d", c.contractSize) }},
		{"verifyProof gas", func(c cost) string { return fmt.Sprintf("%d", c.gas) }},
	} {
		t.Logf("| %-24s | %12s | %12s |", metric.name, metric.get(costs[0]), metric.get(costs[1]))
	}
}

// calldataInputs returns the public inputs verifyProof takes: the circuit's
// public witness minus the ones the commitments are drawn from, which the
// contract recomputes from the commitment points and the committed values.
func calldataInputs(t *testing.T, vk *groth16bn254.VerifyingKey, public witness.Witness) []*big.Int {
	t.Helper()
	vector, ok := public.Vector().(fr.Vector)
	require.True(t, ok)

	// the contract reads the first numWitness public inputs from calldata and
	// derives the rest from the commitments, see lib/solidity's template.
	numPublic := len(vk.G1.K) - 1
	numWitness := numPublic - len(vk.PublicAndCommitmentCommitted)
	require.LessOrEqual(t, numWitness, len(vector), "the public witness holds fewer inputs than the key expects")

	inputs := make([]*big.Int, numWitness)
	for i := range inputs {
		inputs[i] = new(big.Int)
		vector[i].BigInt(inputs[i])
	}
	return inputs
}
