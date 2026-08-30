package solidity_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/internal/soltest"
	"github.com/mistcash/grosh26/solidity"
)

// threeCommitCircuit makes three chained api.Commit calls, the same shape the
// polynomial ring circuits produce (two ring commitments plus the range
// checker's), but small enough to set up in a moment. It also carries a real
// public input: a circuit whose only public values are commitments exports an
// illegal `uint256[0] calldata` parameter.
type threeCommitCircuit struct {
	A, B, C frontend.Variable
	Product frontend.Variable `gnark:",public"`
}

func (c *threeCommitCircuit) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("compiler does not commit")
	}
	commit1, err := committer.Commit(c.A)
	if err != nil {
		return err
	}
	commit2, err := committer.Commit(c.B, commit1)
	if err != nil {
		return err
	}
	commit3, err := committer.Commit(c.C, commit2)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commit1, 0)
	api.AssertIsDifferent(commit2, 0)
	api.AssertIsDifferent(commit3, 0)

	api.AssertIsEqual(api.Mul(api.Mul(c.A, c.B), c.C), c.Product)
	return nil
}

// TestThreeCommitmentsOnChain is the point of this package: gnark's own setup,
// prover and verifier, a circuit with three commitments -- which gnark's
// generator does not support -- and the contract generated here checking the
// proof on a real EVM.
func TestThreeCommitmentsOnChain(t *testing.T) {
	solcPath := soltest.Solc(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &threeCommitCircuit{})
	require.NoError(t, err)

	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)

	fullWitness, err := frontend.NewWitness(&threeCommitCircuit{A: 1, B: 2, C: 3, Product: 6}, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err := fullWitness.Public()
	require.NoError(t, err)

	proof, err := groth16.Prove(ccs, pk, fullWitness, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	require.NoError(t, groth16.Verify(proof, vk, publicWitness, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))

	bnVK, ok := vk.(*groth16bn254.VerifyingKey)
	require.True(t, ok)
	bnProof, ok := proof.(*groth16bn254.Proof)
	require.True(t, ok)
	require.Len(t, bnProof.Commitments, 3)

	var src bytes.Buffer
	require.NoError(t, solidity.ExportSolidity(bnVK, &src))

	deployment := soltest.Deploy(t, solcPath, src.String())
	contract := deployment.Contract

	publicInputs := [1]*big.Int{big.NewInt(6)}
	var results []any
	require.NoError(t,
		contract.Call(&bind.CallOpts{}, &results, "verifyProof", solidity.MarshalSolidity(bnProof), publicInputs),
		"a genuine proof must verify on-chain")

	// tampering with any one of the three commitments must be caught: the
	// folding challenge binds all of them, not just the first
	for i := range bnProof.Commitments {
		tampered := *bnProof
		tampered.Commitments = append([]curve.G1Affine{}, bnProof.Commitments...)

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
	}

	// so must a proof for a different statement
	var out []any
	require.Error(t,
		contract.Call(&bind.CallOpts{}, &out, "verifyProof", solidity.MarshalSolidity(bnProof), [1]*big.Int{big.NewInt(7)}),
		"a proof for different public inputs must be rejected on-chain")
}
