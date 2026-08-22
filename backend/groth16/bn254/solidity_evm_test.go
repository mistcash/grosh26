package groth16_test

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bn254groth16 "github.com/mistcash/grosh26/backend/groth16/bn254"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/stretchr/testify/require"
)

// findSolc locates a solc binary to compile the generated verifier with.
// This test needs an actual Solidity compiler, which isn't something we can
// vendor, so it's opt-in: it skips (rather than fails) if solc isn't
// available, same as gnark's own solidity test suite does.
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

// compileSolidity shells out to solc and returns the ABI and init bytecode
// for the single contract in source.
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

// TestChainedThreeCommitmentsSolidityVerifier compiles the exported
// verifier for the chained three-commitment circuit and runs it against a
// real EVM (go-ethereum's simulated backend), proving the fix end to end
// rather than just at the Go level: a genuine proof verifies on chain, and
// tampering with any one of the three commitments -- not just the first --
// makes the on-chain verifyProof call revert.
func TestChainedThreeCommitmentsSolidityVerifier(t *testing.T) {
	solcPath := findSolc(t)

	circuit := &chainedThreeCommitCircuit{}
	assignment := &chainedThreeCommitCircuit{A: 1, B: 2, C: 3, Product: 6}

	_ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	require.NoError(t, err)
	ccs, ok := _ccs.(*cs.R1CS)
	require.True(t, ok)

	pk := new(bn254groth16.ProvingKey)
	vk := new(bn254groth16.VerifyingKey)
	require.NoError(t, bn254groth16.Setup(ccs, pk, vk))

	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	proof, err := bn254groth16.Prove(ccs, pk, w, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)
	require.Len(t, proof.Commitments, 3)

	publicWitness, err := w.Public()
	require.NoError(t, err)
	publicVector, ok := publicWitness.Vector().(fr.Vector)
	require.True(t, ok)
	require.NoError(t, bn254groth16.Verify(proof, vk, publicVector, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))

	var solSrc bytes.Buffer
	require.NoError(t, vk.ExportSolidity(&solSrc))

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

	// only Product (index 0) is a public, non-commitment witness value here
	publicInputs := [1]*big.Int{new(big.Int).SetUint64(6)}

	var results []any
	err = boundContract.Call(&bind.CallOpts{}, &results, "verifyProof", proof.MarshalSolidity(), publicInputs)
	require.NoError(t, err, "a genuine proof must verify on-chain")

	// Tamper with each of the three commitments in turn (not just the
	// first) and confirm the on-chain verifier rejects every one. Before
	// the fix, tampering with commitments[1] or commitments[2] would have
	// gone undetected since only commitments[0]'s proof of knowledge was
	// checked.
	for i := 0; i < len(proof.Commitments); i++ {
		tampered := *proof
		tampered.Commitments = append([]curve.G1Affine{}, proof.Commitments...)

		var s fr.Element
		_, err := s.SetRandom()
		require.NoError(t, err)
		var sBig big.Int
		s.BigInt(&sBig)
		tampered.Commitments[i].ScalarMultiplicationBase(&sBig)

		var tamperedResults []any
		err = boundContract.Call(&bind.CallOpts{}, &tamperedResults, "verifyProof", tampered.MarshalSolidity(), publicInputs)
		require.Errorf(t, err, "tampering with commitments[%d] must be rejected on-chain", i)
	}
}
