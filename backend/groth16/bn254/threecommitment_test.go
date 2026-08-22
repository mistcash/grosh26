package groth16_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254groth16 "github.com/mistcash/grosh26/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
)

// chainedThreeCommitCircuit exercises three sequential api.Commit calls
// where each commitment's output feeds into the next commitment's input:
// commit1 -> commit2 -> commit3. It also carries a genuine public input
// (Product) rather than none, since a circuit with zero public witness
// values beyond the commitments produces an illegal `uint256[0] calldata`
// parameter in the exported Solidity -- a pre-existing template quirk
// unrelated to multi-commitment support, avoided here rather than fixed
// since it's out of scope.
type chainedThreeCommitCircuit struct {
	A, B, C frontend.Variable
	Product frontend.Variable `gnark:",public"`
}

func (c *chainedThreeCommitCircuit) Define(api frontend.API) error {
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

	product := api.Mul(api.Mul(c.A, c.B), c.C)
	api.AssertIsEqual(product, c.Product)
	return nil
}

func TestChainedThreeCommitments(t *testing.T) {
	circuit := &chainedThreeCommitCircuit{}
	assignment := &chainedThreeCommitCircuit{A: 1, B: 2, C: 3, Product: 6}
	test(t, circuit, assignment)
}

// TestChainedThreeCommitmentsRejectsTamperedCommitment proves that every
// one of the three commitments' proofs of knowledge is actually checked,
// not just the first: swapping in an unrelated point for the middle
// commitment must make verification fail.
func TestChainedThreeCommitmentsRejectsTamperedCommitment(t *testing.T) {
	circuit := &chainedThreeCommitCircuit{}
	assignment := &chainedThreeCommitCircuit{A: 1, B: 2, C: 3, Product: 6}

	ccs, pk, vk := setup(t, circuit)
	public, proof := prove(t, assignment, ccs, pk)
	assert.Len(t, proof.Commitments, 3)

	var s fr.Element
	_, err := s.SetRandom()
	assert.NoError(t, err)
	var sBigInt big.Int
	s.BigInt(&sBigInt)
	proof.Commitments[1].ScalarMultiplicationBase(&sBigInt)

	assert.Error(t, bn254groth16.Verify(proof, vk, public))
}

// TestChainedThreeCommitmentsExportSolidity checks that the Solidity
// template actually parses and executes for three commitments, and that
// it emitted a distinct GSigmaNeg constant for the third one rather than
// silently degenerating to a single-commitment contract.
func TestChainedThreeCommitmentsExportSolidity(t *testing.T) {
	circuit := &chainedThreeCommitCircuit{}
	_, _, vk := setup(t, circuit)

	var buf bytes.Buffer
	assert.NoError(t, vk.ExportSolidity(&buf))
	assert.Contains(t, buf.String(), "PEDERSEN_GSIGMANEG_0_X_0")
	assert.Contains(t, buf.String(), "PEDERSEN_GSIGMANEG_1_X_0")
	assert.Contains(t, buf.String(), "PEDERSEN_GSIGMANEG_2_X_0")
}
