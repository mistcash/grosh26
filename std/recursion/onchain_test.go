package recursion_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/internal/soltest"
	"github.com/mistcash/grosh26/internal/timing"
	"github.com/mistcash/grosh26/solidity"
	"github.com/mistcash/grosh26/std/recursion"
)

// TestOuterOnChain proves the outer recursive circuit for real, generates its
// Solidity verifier with the multi-commitment generator, and runs the genuine
// proof -- plus tampered and mismatched variants -- against it on a simulated
// EVM. Compiling and proving the outer circuit (well over a million
// constraints) dominates, so it is skipped under -short like the repo's other
// on-chain tests.
func TestOuterOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the full outer circuit setup under -short")
	}
	solcPath := soltest.Solc(t)

	fx := newInnerFixture(t)

	outerVK, err := recursion.NewVerifyingKey(fx.vk)
	require.NoError(t, err)

	start := time.Now()
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(outerVK))
	require.NoError(t, err)
	t.Logf("outer r1cs compiled in %s: %d constraints, %d public inputs",
		timing.Since(start), outerCcs.GetNbConstraints(), outerCcs.GetNbPublicVariables()-1)

	start = time.Now()
	outerPK, outerVKGnark, err := groth16.Setup(outerCcs)
	require.NoError(t, err)
	t.Logf("outer groth16 setup in %s", timing.Since(start))

	outerProofField, err := recursion.ValueOfProof(fx.proof)
	require.NoError(t, err)
	outerAssignment := &recursion.Circuit{
		Proof:         outerProofField,
		PublicWitness: recursion.ValueOfPublicWitness(fx.public),
	}
	outerFullWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	outerPublicWitness, err := outerFullWitness.Public()
	require.NoError(t, err)

	start = time.Now()
	outerProof, err := groth16.Prove(outerCcs, outerPK, outerFullWitness, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	t.Logf("outer groth16 prove in %s", timing.Since(start))

	start = time.Now()
	require.NoError(t, groth16.Verify(outerProof, outerVKGnark, outerPublicWitness, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))
	t.Logf("outer groth16 verify in %s", timing.Since(start))

	outerBnVK, ok := outerVKGnark.(*groth16backend.VerifyingKey)
	require.True(t, ok)
	outerBnProof, ok := outerProof.(*groth16backend.Proof)
	require.True(t, ok)
	require.Len(t, outerBnProof.Commitments, 3, "outer proof carries the ring checks' two commitments plus the range checker's")

	var src bytes.Buffer
	require.NoError(t, solidity.ExportSolidity(outerBnVK, &src))
	deployment := soltest.Deploy(t, solcPath, src.String())
	contract := deployment.Contract

	vector, ok := outerPublicWitness.Vector().(fr.Vector)
	require.True(t, ok)
	require.Len(t, vector, outerCcs.GetNbPublicVariables()-1)

	publicInputs := make([]*big.Int, len(vector))
	for i := range vector {
		publicInputs[i] = new(big.Int)
		vector[i].BigInt(publicInputs[i])
	}
	genuineProofBytes := solidity.MarshalSolidity(outerBnProof)
	t.Logf("outer proof: %d bytes, %d public inputs", len(genuineProofBytes), len(publicInputs))

	var results []any
	require.NoError(t,
		contract.Call(&bind.CallOpts{}, &results, "verifyProof", genuineProofBytes, publicInputs),
		"a genuine outer proof must verify on-chain")

	receipt := deployment.Send(t, "verifyProof", genuineProofBytes, publicInputs)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	t.Logf("verifyProof: %d gas (outer proof, 3 commitments)", receipt.GasUsed)

	// tampering with any one of the three commitments must be caught: the
	// folding challenge binds all of them, not just the first. Matches the
	// struct-mutation pattern in solidity/solidity_test.go's
	// TestThreeCommitmentsOnChain, immune to MarshalSolidity layout changes.
	for i := range outerBnProof.Commitments {
		t.Run(fmt.Sprintf("TamperCommitment%d", i), func(t *testing.T) {
			tampered := *outerBnProof
			tampered.Commitments = append([]curve.G1Affine{}, outerBnProof.Commitments...)

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
		contract.Call(&bind.CallOpts{}, &out, "verifyProof", genuineProofBytes, wrongInputs),
		"a proof for different public inputs must be rejected on-chain")
}
