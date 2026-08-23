package fq12

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/stretchr/testify/require"

	bn254groth16 "github.com/mistcash/grosh26/backend/groth16/bn254"
)

// nbPublicInputs is the size of the input array the generated verifier takes:
// Y's twelve emulated coefficients, four limbs each.
const nbPublicInputs = 48

// findSolc locates a solc binary to compile the generated verifier with. This
// test needs an actual Solidity compiler, which isn't something we can vendor,
// so it's opt-in: it skips (rather than fails) if solc isn't available.
func findSolc(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOLC_BIN"); p != "" {
		return p
	}
	p, err := exec.LookPath("solc")
	if err != nil {
		t.Skip("solc not found (set SOLC_BIN or put solc on PATH) - skipping on-chain verifier test")
	}
	return p
}

// compileSolidity shells out to solc and returns the ABI and init bytecode for
// the single contract in source.
func compileSolidity(t *testing.T, solcPath, source string) (abi.ABI, []byte) {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "Verifier.sol")
	require.NoError(t, os.WriteFile(srcPath, []byte(source), 0o600))

	cmd := exec.Command(solcPath, "--optimize", "--combined-json", "abi,bin", srcPath)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("solc failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("solc failed: %v", err)
	}

	var parsed struct {
		Contracts map[string]struct {
			Abi json.RawMessage `json:"abi"`
			Bin string          `json:"bin"`
		} `json:"contracts"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed.Contracts, 1, "expected solc to emit exactly one contract")

	var abiJSON json.RawMessage
	var bytecodeHex string
	for _, c := range parsed.Contracts {
		abiJSON, bytecodeHex = c.Abi, c.Bin
	}
	require.NotEmpty(t, bytecodeHex, "solc produced empty bytecode")

	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	require.NoError(t, err)
	return parsedABI, common.FromHex(bytecodeHex)
}

// TestSolidityVerifier is the end-to-end check the binary automates: prove the
// 𝔽p¹² ring circuit with gnark's Groth16 prover, generate the verifier with
// this repository's Solidity generator, and run the two against each other on a
// real EVM. The circuit draws three commitments -- two for the polynomial ring
// checks and one for the range checker -- so it also exercises the generator's
// multi-commitment handling.
//
// It also pins the one incompatibility that comes with those three
// commitments: a proof from the upstream gnark prover verifies off chain but is
// rejected by the contract, because upstream folds the commitments' proofs of
// knowledge with an fr.Hash challenge the contract cannot recompute.
func TestSolidityVerifier(t *testing.T) {
	solcPath := findSolc(t)

	_ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	require.NoError(t, err)
	ccs, ok := _ccs.(*cs.R1CS)
	require.True(t, ok)

	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)

	assignment, err := AssignRandom()
	require.NoError(t, err)

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err := fullWitness.Public()
	require.NoError(t, err)

	// the setup is gnark's; the keys are re-read into the local backend, whose
	// Prove and ExportSolidity agree on how the commitment challenges are made
	localPK, localVK := new(bn254groth16.ProvingKey), new(bn254groth16.VerifyingKey)
	requireReserialize(t, pk, localPK)
	requireReserialize(t, vk, localVK)
	require.Len(t, localVK.PublicAndCommitmentCommitted, 3, "expected three commitments")

	localProof, err := bn254groth16.Prove(ccs, localPK, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	vector, ok := publicWitness.Vector().(fr.Vector)
	require.True(t, ok)
	require.NoError(t, bn254groth16.Verify(localProof, localVK, vector, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))

	// the same statement proved by the upstream prover, which also verifies off
	// chain -- with the upstream verifier
	upstreamProof, err := groth16.Prove(ccs, pk, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	require.NoError(t, groth16.Verify(upstreamProof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))
	upstreamLocal := new(bn254groth16.Proof)
	requireReserialize(t, upstreamProof, upstreamLocal)

	// export the verifier with our generator, not gnark's
	var solSrc bytes.Buffer
	require.NoError(t, localVK.ExportSolidity(&solSrc))

	parsedABI, bytecode := compileSolidity(t, solcPath, solSrc.String())

	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	sim := simulated.NewBackend(types.GenesisAlloc{
		addr: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)},
	})
	defer sim.Close()
	client := sim.Client()

	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	require.NoError(t, err)

	contractAddr, deployTx, boundContract, err := bind.DeployContract(auth, parsedABI, bytecode, client)
	require.NoError(t, err)
	sim.Commit()

	receipt, err := bind.WaitMined(t.Context(), client, deployTx)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "verifier contract deployment failed")
	require.NotEqual(t, common.Address{}, contractAddr)

	require.Len(t, vector, nbPublicInputs)

	var publicInputs [nbPublicInputs]*big.Int
	for i := range vector {
		publicInputs[i] = new(big.Int)
		vector[i].BigInt(publicInputs[i])
	}

	var results []any
	require.NoError(t,
		boundContract.Call(&bind.CallOpts{}, &results, "verifyProof", localProof.MarshalSolidity(), publicInputs),
		"a genuine proof must verify on-chain")

	// a public input that isn't the one proved must be rejected
	tampered := publicInputs
	tampered[0] = new(big.Int).Add(publicInputs[0], big.NewInt(1))
	var tamperedResults []any
	require.Error(t,
		boundContract.Call(&bind.CallOpts{}, &tamperedResults, "verifyProof", localProof.MarshalSolidity(), tampered),
		"a proof for different public inputs must be rejected on-chain")

	// and the upstream prover's proof, valid as it is off chain, is not one the
	// contract can check
	var upstreamResults []any
	require.Error(t,
		boundContract.Call(&bind.CallOpts{}, &upstreamResults, "verifyProof", upstreamLocal.MarshalSolidity(), publicInputs),
		"the contract cannot recompute the upstream prover's commitment folding challenge")
}

// requireReserialize round-trips src through its serialised form into dst. The
// local backend's key and proof types have the same layout as gnark's, so this
// is how a gnark setup is handed to the local prover and generator.
func requireReserialize(t *testing.T, src io.WriterTo, dst io.ReaderFrom) {
	t.Helper()
	var buf bytes.Buffer
	_, err := src.WriteTo(&buf)
	require.NoError(t, err)
	_, err = dst.ReadFrom(&buf)
	require.NoError(t, err)
}
