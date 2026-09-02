package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/mistcash/grosh26/circuits/poseidon"
	"github.com/mistcash/grosh26/internal/timing"
	"github.com/mistcash/grosh26/solidity"
	"github.com/mistcash/grosh26/std/recursion"
)

// Artifact filenames.
const (
	innerR1csFile = "inner.r1cs"
	innerPKFile   = "inner.pk"
	innerVKFile   = "inner.vk"

	outerR1csFile = "outer.r1cs"
	outerPKFile   = "outer.pk"
	outerVKFile   = "outer.vk"
	solidityFile  = "Verifier.sol"
	proofFile     = "outer.proof"
	witnessFile   = "outer.public.wtns"
	calldataFile  = "calldata.json"

	// outerFingerprintFile records the sha256 digest of the inner.vk the outer
	// artifacts were compiled against, so cmdProve can detect a stale or
	// mismatched artifact set instead of failing opaquely at proving time.
	outerFingerprintFile = "outer.inner-vk.sha256"
)

// cmdSetup compiles the inner and outer circuits and runs their Groth16
// setups. The outer verifying key bakes in the inner verifying key as
// compile-time constants, so the inner setup has to run first; both inner
// artifacts are persisted so a later cmdProve reuses the exact inner
// verifying key the outer circuit was compiled against, rather than an inner
// setup rerun -- which would produce a fresh, mismatched verifying key.
func cmdSetup(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	start := time.Now()
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poseidon.Circuit{})
	if err != nil {
		return fmt.Errorf("compile inner circuit: %w", err)
	}
	fmt.Printf("inner compiled in %s: %d constraints, %d public inputs\n",
		timing.Since(start), innerCcs.GetNbConstraints(), innerCcs.GetNbPublicVariables()-1)

	start = time.Now()
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return fmt.Errorf("inner groth16 setup: %w", err)
	}
	fmt.Printf("inner setup done in %s\n", timing.Since(start))

	innerBnVK, ok := innerVK.(*groth16bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("unexpected inner verifying key type %T", innerVK)
	}
	if err := writeAll(map[string]io.WriterTo{
		filepath.Join(dir, innerR1csFile): innerCcs,
		filepath.Join(dir, innerPKFile):   innerPK,
		filepath.Join(dir, innerVKFile):   innerVK,
	}); err != nil {
		return err
	}
	innerFingerprint, err := fingerprintVK(innerVK)
	if err != nil {
		return fmt.Errorf("fingerprint inner verifying key: %w", err)
	}

	outerVK, err := recursion.NewVerifyingKey(innerBnVK)
	if err != nil {
		return fmt.Errorf("bake inner verifying key: %w", err)
	}

	start = time.Now()
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(outerVK))
	if err != nil {
		return fmt.Errorf("compile outer circuit: %w", err)
	}
	fmt.Printf("outer compiled in %s: %d constraints, %d public inputs\n",
		timing.Since(start), outerCcs.GetNbConstraints(), outerCcs.GetNbPublicVariables()-1)

	start = time.Now()
	outerPK, outerGnarkVK, err := groth16.Setup(outerCcs)
	if err != nil {
		return fmt.Errorf("outer groth16 setup: %w", err)
	}
	fmt.Printf("outer setup done in %s\n", timing.Since(start))

	if err := writeAll(map[string]io.WriterTo{
		filepath.Join(dir, outerR1csFile): outerCcs,
		filepath.Join(dir, outerPKFile):   outerPK,
		filepath.Join(dir, outerVKFile):   outerGnarkVK,
	}); err != nil {
		return err
	}
	// record which inner.vk the outer artifacts above were compiled against,
	// so cmdProve can catch a partial setup rerun or artifacts copied in from
	// a different build instead of failing opaquely at prove time.
	if err := writeString(filepath.Join(dir, outerFingerprintFile), innerFingerprint); err != nil {
		return err
	}
	return exportSolidity(dir, outerGnarkVK)
}

// cmdProve proves the inner circuit for a fresh random preimage, then proves
// the outer circuit over that inner proof, against the inner and outer
// artifacts cmdSetup wrote.
func cmdProve(dir string) error {
	innerCcs := groth16.NewCS(ecc.BN254)
	if err := readFrom(filepath.Join(dir, innerR1csFile), innerCcs); err != nil {
		return err
	}
	innerPK := groth16.NewProvingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, innerPKFile), innerPK); err != nil {
		return err
	}
	innerVK := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, innerVKFile), innerVK); err != nil {
		return err
	}
	if err := checkOuterFingerprint(dir, innerVK); err != nil {
		return err
	}

	innerAssignment, err := poseidon.AssignRandom()
	if err != nil {
		return fmt.Errorf("random inner preimage: %w", err)
	}
	innerFullWitness, err := frontend.NewWitness(innerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("build inner witness: %w", err)
	}

	start := time.Now()
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerFullWitness)
	if err != nil {
		return fmt.Errorf("prove inner: %w", err)
	}
	fmt.Printf("inner proved in %s\n", timing.Since(start))

	innerBnProof, ok := innerProof.(*groth16bn254.Proof)
	if !ok {
		return fmt.Errorf("unexpected inner proof type %T", innerProof)
	}
	innerPublicWitness, err := innerFullWitness.Public()
	if err != nil {
		return fmt.Errorf("inner public witness: %w", err)
	}
	if err := groth16.Verify(innerProof, innerVK, innerPublicWitness); err != nil {
		return fmt.Errorf("inner proof did not verify: %w", err)
	}
	innerVector, ok := innerPublicWitness.Vector().(fr.Vector)
	if !ok {
		return fmt.Errorf("unexpected inner public witness vector type %T", innerPublicWitness.Vector())
	}

	outerCcs := groth16.NewCS(ecc.BN254)
	if err := readFrom(filepath.Join(dir, outerR1csFile), outerCcs); err != nil {
		return err
	}
	outerPK := groth16.NewProvingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, outerPKFile), outerPK); err != nil {
		return err
	}

	outerProofField, err := recursion.ValueOfProof(innerBnProof)
	if err != nil {
		return fmt.Errorf("outer witness for inner proof: %w", err)
	}
	outerAssignment := &recursion.Circuit{
		Proof:         outerProofField,
		PublicWitness: recursion.ValueOfPublicWitness(innerVector),
	}

	outerFullWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("build outer witness: %w", err)
	}
	outerPublicWitness, err := outerFullWitness.Public()
	if err != nil {
		return fmt.Errorf("outer public witness: %w", err)
	}

	start = time.Now()
	outerProof, err := groth16.Prove(outerCcs, outerPK, outerFullWitness, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		return fmt.Errorf("prove outer: %w", err)
	}
	fmt.Printf("outer proved in %s\n", timing.Since(start))

	if err := writeTo(filepath.Join(dir, proofFile), outerProof); err != nil {
		return err
	}
	if err := writeTo(filepath.Join(dir, witnessFile), outerPublicWitness); err != nil {
		return err
	}
	return writeCalldata(dir, outerProof, outerPublicWitness)
}

func cmdVerify(dir string) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, outerVKFile), vk); err != nil {
		return err
	}
	proof := groth16.NewProof(ecc.BN254)
	if err := readFrom(filepath.Join(dir, proofFile), proof); err != nil {
		return err
	}
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("new witness: %w", err)
	}
	if err := readFrom(filepath.Join(dir, witnessFile), publicWitness); err != nil {
		return err
	}

	if err := groth16.Verify(proof, vk, publicWitness, gnarksolidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Println("outer proof verified")
	return nil
}

func cmdSolidity(dir string) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, outerVKFile), vk); err != nil {
		return err
	}
	return exportSolidity(dir, vk)
}

func exportSolidity(dir string, vk groth16.VerifyingKey) error {
	bnVK, ok := vk.(*groth16bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("unexpected verifying key type %T", vk)
	}

	path := filepath.Join(dir, solidityFile)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if err := solidity.ExportSolidity(bnVK, f); err != nil {
		return fmt.Errorf("export solidity: %w", err)
	}
	fmt.Printf("wrote %s (%d public inputs, %d commitments)\n", path,
		len(bnVK.G1.K)-1-len(bnVK.PublicAndCommitmentCommitted), len(bnVK.PublicAndCommitmentCommitted))
	return nil
}

// writeCalldata writes what a caller hands the outer verifier contract: the
// outer proof in the packed form verifyProof expects, and its public inputs.
func writeCalldata(dir string, proof groth16.Proof, publicWitness witness.Witness) error {
	bnProof, ok := proof.(*groth16bn254.Proof)
	if !ok {
		return fmt.Errorf("unexpected proof type %T", proof)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		return fmt.Errorf("unexpected public witness vector type %T", publicWitness.Vector())
	}

	inputs := make([]string, len(vector))
	for i := range vector {
		var b big.Int
		vector[i].BigInt(&b)
		inputs[i] = b.String()
	}

	data, err := json.MarshalIndent(struct {
		Proof  string   `json:"proof"`
		Inputs []string `json:"input"`
	}{
		Proof:  "0x" + hex.EncodeToString(solidity.MarshalSolidity(bnProof)),
		Inputs: inputs,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode calldata: %w", err)
	}

	path := filepath.Join(dir, calldataFile)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

// fingerprintVK returns a stable hex digest of vk's serialized bytes, used to
// check whether outer artifacts on disk were compiled against a particular
// inner verifying key.
func fingerprintVK(vk io.WriterTo) (string, error) {
	h := sha256.New()
	if _, err := vk.WriteTo(h); err != nil {
		return "", fmt.Errorf("hash verifying key: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkOuterFingerprint fails loudly if the outer artifacts in dir were not
// compiled against innerVK: it compares innerVK's fingerprint against the one
// cmdSetup recorded alongside the outer artifacts when it built the outer
// circuit around this exact inner verifying key. Without this, a partial or
// interrupted setup rerun, or outer artifacts copied in from a different
// build, would surface only as an opaque "constraint not satisfied" failure
// deep inside cmdProve's outer groth16.Prove call.
func checkOuterFingerprint(dir string, innerVK io.WriterTo) error {
	got, err := fingerprintVK(innerVK)
	if err != nil {
		return fmt.Errorf("fingerprint inner verifying key: %w", err)
	}
	path := filepath.Join(dir, outerFingerprintFile)
	recorded, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: outer artifacts predate consistency fingerprinting, or setup was interrupted before finishing; re-run 'grosh26 setup' to produce a consistent artifact set (%w)", path, err)
	}
	if want := strings.TrimSpace(string(recorded)); got != want {
		return fmt.Errorf("outer artifacts in %s do not match inner.vk on disk (inner.vk fingerprint %s, outer artifacts were built against %s); re-run 'grosh26 setup' to produce a consistent artifact set", dir, got, want)
	}
	return nil
}

// writeString writes s (plus a trailing newline) to path.
func writeString(path, s string) error {
	if err := os.WriteFile(path, []byte(s+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

// writeAll writes every path/value pair in deterministic (sorted-path) order,
// stopping at the first error.
func writeAll(files map[string]io.WriterTo) error {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := writeTo(path, files[path]); err != nil {
			return err
		}
	}
	return nil
}

func writeTo(path string, v io.WriterTo) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	n, err := v.WriteTo(f)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, n)
	return nil
}

func readFrom(path string, v io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if _, err := v.ReadFrom(f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
