// Command grosh26 drives the polynomial ring pairing circuit end to end: it
// compiles the circuit, runs gnark's Groth16 setup, exports the proving and
// verifying keys, proves and verifies with gnark, and generates the Solidity
// verifier with this repository's generator.
//
//	grosh26 setup      compile, set up, write circuit.r1cs, circuit.pk, circuit.vk, Verifier.sol
//	grosh26 prove      prove, write proof.bin, public.wtns, calldata.json
//	grosh26 verify     verify proof.bin against circuit.vk
//	grosh26 solidity   regenerate Verifier.sol from circuit.vk
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
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

	"github.com/mistcash/grosh26/circuits/pairing"
	"github.com/mistcash/grosh26/solidity"
)

const (
	r1csFile     = "circuit.r1cs"
	pkFile       = "circuit.pk"
	vkFile       = "circuit.vk"
	solidityFile = "Verifier.sol"
	proofFile    = "proof.bin"
	witnessFile  = "public.wtns"
	calldataFile = "calldata.json"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "grosh26:", err)
		os.Exit(1)
	}
}

const usage = `usage: grosh26 <command> [-dir <artifacts>]

commands:
  setup      compile the circuit, run the Groth16 setup, write the keys and
             export the Solidity verifier
  prove      build a witness, prove it and write the proof, its public inputs
             and the verifier calldata
  verify     verify a proof against the verifying key
  solidity   regenerate the Solidity verifier from the verifying key
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}
	cmd, args := args[0], args[1:]

	fs := flag.NewFlagSet("grosh26 "+cmd, flag.ContinueOnError)
	dir := fs.String("dir", "build", "directory holding the circuit artifacts")

	var fn func(string) error
	switch cmd {
	case "setup":
		fn = cmdSetup
	case "prove":
		fn = cmdProve
	case "verify":
		fn = cmdVerify
	case "solidity":
		fn = cmdSolidity
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fn(*dir)
}

// cmdSetup compiles the circuit and runs gnark's Groth16 setup. The Solidity
// verifier is exported here too, so one command produces everything needed to
// prove and to verify on chain.
func cmdSetup(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairing.Circuit{})
	if err != nil {
		return fmt.Errorf("compile circuit: %w", err)
	}
	fmt.Printf("compiled in %s: %d constraints, %d public inputs\n",
		since(start), ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)

	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("groth16 setup: %w", err)
	}
	fmt.Printf("setup done in %s\n", since(start))

	for path, v := range map[string]io.WriterTo{
		filepath.Join(dir, r1csFile): ccs,
		filepath.Join(dir, pkFile):   pk,
		filepath.Join(dir, vkFile):   vk,
	} {
		if err := writeTo(path, v); err != nil {
			return err
		}
	}
	return exportSolidity(dir, vk)
}

func cmdProve(dir string) error {
	ccs := groth16.NewCS(ecc.BN254)
	if err := readFrom(filepath.Join(dir, r1csFile), ccs); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, pkFile), pk); err != nil {
		return err
	}

	assignment, err := pairing.AssignRandom()
	if err != nil {
		return err
	}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("build witness: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}

	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, fullWitness, gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	fmt.Printf("proved in %s\n", since(start))

	if err := writeTo(filepath.Join(dir, proofFile), proof); err != nil {
		return err
	}
	if err := writeTo(filepath.Join(dir, witnessFile), publicWitness); err != nil {
		return err
	}
	return writeCalldata(dir, proof, publicWitness)
}

func cmdVerify(dir string) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, vkFile), vk); err != nil {
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
	fmt.Println("proof verified")
	return nil
}

func cmdSolidity(dir string) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFrom(filepath.Join(dir, vkFile), vk); err != nil {
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

// writeCalldata writes what a caller hands the on-chain verifier: the proof in
// the packed form verifyProof expects, and the public inputs.
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

func since(start time.Time) time.Duration { return time.Since(start).Round(time.Millisecond) }

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
