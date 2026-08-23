// Package soltest deploys a generated verifier to a simulated EVM, so tests can
// check a contract against a real proof rather than only against its source.
package soltest

import (
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/stretchr/testify/require"
)

// Solc locates a Solidity compiler. One is not something we can vendor, so a
// caller with none skips rather than fails.
func Solc(t *testing.T) string {
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

// Deploy compiles source, which must hold exactly one contract, and deploys it
// to a simulated chain torn down with the test.
func Deploy(t *testing.T, solcPath, source string) *bind.BoundContract {
	t.Helper()

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "Verifier.sol")
	require.NoError(t, os.WriteFile(srcPath, []byte(source), 0o600))

	out, err := exec.Command(solcPath, "--optimize", "--combined-json", "abi,bin", srcPath).Output()
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

	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(key.PublicKey)

	sim := simulated.NewBackend(types.GenesisAlloc{
		addr: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)},
	})
	t.Cleanup(func() { sim.Close() })

	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	require.NoError(t, err)

	_, deployTx, contract, err := bind.DeployContract(auth, parsedABI, common.FromHex(bytecodeHex), sim.Client())
	require.NoError(t, err)
	sim.Commit()

	receipt, err := bind.WaitMined(t.Context(), sim.Client(), deployTx)
	require.NoError(t, err)
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "verifier contract deployment failed")

	return contract
}
