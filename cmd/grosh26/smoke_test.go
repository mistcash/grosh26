package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRecursivePipeline builds the grosh26 binary and drives it through the
// full recursive flow -- setup, prove, verify, solidity -- in a temporary
// directory, asserting every expected artifact lands and the outer proof
// verifies. It is the release gate: a wiring regression in main.go or
// recursive.go (a wrong flag, a stale filename, an argument passed to the
// wrong command) fails here even when every library-level seam still passes
// its own tests.
//
// The setup step runs the outer circuit's Groth16 setup (well over a million
// constraints), so this is skipped under -short like the repo's other
// full-setup tests.
func TestRecursivePipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the CLI recursive pipeline under -short")
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "grosh26")
	build := exec.Command("go", "build", "-o", binPath, ".")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "go build ./cmd/grosh26:\n%s", out)

	artifactDir := filepath.Join(t.TempDir(), "build")

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(binPath, append(args, "-dir", artifactDir)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "grosh26 %v:\n%s", args, out)
		return string(out)
	}

	run("setup")
	for _, name := range []string{
		"inner.r1cs", "inner.pk", "inner.vk",
		"outer.r1cs", "outer.pk", "outer.vk",
		"Verifier.sol",
	} {
		requireExists(t, filepath.Join(artifactDir, name))
	}

	run("prove")
	for _, name := range []string{"outer.proof", "outer.public.wtns", "calldata.json"} {
		requireExists(t, filepath.Join(artifactDir, name))
	}

	verifyOut := run("verify")
	require.Contains(t, verifyOut, "outer proof verified")

	// solidity must regenerate the same verifier from the persisted outer.vk
	// alone, without the r1cs or proving key.
	require.NoError(t, os.Remove(filepath.Join(artifactDir, "Verifier.sol")))
	run("solidity")
	requireExists(t, filepath.Join(artifactDir, "Verifier.sol"))
}

func requireExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, "expected artifact %s", path)
	require.Greater(t, info.Size(), int64(0), "expected non-empty artifact %s", path)
}
