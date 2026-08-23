// Command fq12 drives the 𝔽p¹² polynomial ring circuit end to end: it runs the
// Groth16 setup and exports the proving and verifying keys, produces proofs
// with gnark's Groth16 prover, and generates the Solidity verifier with this
// repository's generator rather than gnark's.
//
//	fq12 setup                  compile, set up, write circuit.r1cs, circuit.pk, circuit.vk, Verifier.sol
//	fq12 prove -seed hello      prove, write proof.bin, public.wtns, calldata.json
//	fq12 verify                 verify proof.bin against circuit.vk
//	fq12 solidity               regenerate Verifier.sol from circuit.vk
//
// prove and verify take -upstream to swap this repository's vendored gnark
// prover for the one in github.com/consensys/gnark; see [cmdProve] for why the
// exported contract only accepts proofs from the former.
package main

import (
	"bytes"
	"crypto/sha256"
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
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	bn254groth16 "github.com/mistcash/grosh26/backend/groth16/bn254"
	"github.com/mistcash/grosh26/circuits/fq12"
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
		fmt.Fprintln(os.Stderr, "fq12:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: fq12 <command> [flags]

commands:
  setup      compile the circuit, run the Groth16 setup, write the proving and
             verifying keys and export the Solidity verifier
  prove      build a witness, prove it with gnark's prover and write the proof,
             its public inputs and the verifier calldata
  verify     verify a proof against the verifying key
  solidity   (re)generate the Solidity verifier from the verifying key

run "fq12 <command> -h" for the flags of a command
`)
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}

	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("fq12 "+cmd, flag.ContinueOnError)
	dir := fs.String("dir", "build", "directory holding the circuit artifacts")

	switch cmd {
	case "setup":
		if err := fs.Parse(args); err != nil {
			return err
		}
		return cmdSetup(*dir)
	case "prove":
		seed := fs.String("seed", "", "derive the secret 𝔽p¹² base from this seed; random when empty")
		upstream := fs.Bool("upstream", false, "prove with the upstream gnark prover instead of this repository's; the exported contract rejects such proofs, see cmdProve")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return cmdProve(*dir, *seed, *upstream)
	case "verify":
		upstream := fs.Bool("upstream", false, "verify a proof made with -upstream")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return cmdVerify(*dir, *upstream)
	case "solidity":
		if err := fs.Parse(args); err != nil {
			return err
		}
		return cmdSolidity(*dir)
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// cmdSetup compiles the circuit and runs the Groth16 setup. The Solidity
// verifier is exported here too, so a single command produces everything
// needed to prove and to verify on chain.
func cmdSetup(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	start := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fq12.Circuit{})
	if err != nil {
		return fmt.Errorf("compile circuit: %w", err)
	}
	fmt.Printf("compiled in %s: %d constraints, %d public inputs\n",
		time.Since(start).Round(time.Millisecond), ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)

	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("groth16 setup: %w", err)
	}
	fmt.Printf("setup done in %s\n", time.Since(start).Round(time.Millisecond))

	if err := writeTo(filepath.Join(dir, r1csFile), ccs); err != nil {
		return err
	}
	if err := writeTo(filepath.Join(dir, pkFile), pk); err != nil {
		return err
	}
	if err := writeTo(filepath.Join(dir, vkFile), vk); err != nil {
		return err
	}
	if err := exportSolidity(dir, vk); err != nil {
		return err
	}
	return nil
}

// cmdProve proves the circuit. The proof is targeted at the Solidity verifier,
// which fixes how the commitment challenges are derived.
//
// Both provers here are gnark's Groth16 prover; upstream is the one in
// github.com/consensys/gnark, and the default is this repository's vendored
// copy of it. They differ in one place that matters on chain: this circuit
// draws three commitments (two for the polynomial ring checks, one for the
// range checker), and upstream folds their proofs of knowledge with a challenge
// from fr.Hash's expand_message_xmd, which the generated contract has no
// affordable way to recompute. The vendored prover routes that challenge
// through the same keccak hasher as the rest of the Solidity target. Proofs
// from the upstream prover verify off chain but are rejected by the contract,
// so -upstream is here to reproduce that, not to produce usable proofs.
func cmdProve(dir, seed string, upstream bool) error {
	ccs := groth16.NewCS(ecc.BN254)
	if err := readFrom(filepath.Join(dir, r1csFile), ccs); err != nil {
		return err
	}

	base, err := baseFromSeed(seed)
	if err != nil {
		return err
	}
	assignment := fq12.Assign(base)

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("build witness: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}

	var proof io.WriterTo
	start := time.Now()
	if upstream {
		pk := groth16.NewProvingKey(ecc.BN254)
		if err := readFrom(filepath.Join(dir, pkFile), pk); err != nil {
			return err
		}
		fmt.Println("proving with the upstream gnark prover; the exported contract will reject this proof")
		proof, err = groth16.Prove(ccs, pk, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	} else {
		sys, ok := ccs.(*cs.R1CS)
		if !ok {
			return fmt.Errorf("unexpected constraint system type %T", ccs)
		}
		pk := new(bn254groth16.ProvingKey)
		if err := readFrom(filepath.Join(dir, pkFile), pk); err != nil {
			return err
		}
		proof, err = bn254groth16.Prove(sys, pk, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	}
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	fmt.Printf("proved in %s\n", time.Since(start).Round(time.Millisecond))

	if err := writeTo(filepath.Join(dir, proofFile), proof); err != nil {
		return err
	}
	if err := writeTo(filepath.Join(dir, witnessFile), publicWitness); err != nil {
		return err
	}
	return writeCalldata(dir, proof, publicWitness)
}

// cmdVerify verifies the proof off chain, with the same commitment challenge
// derivation the Solidity verifier uses. Pass -upstream to verify a proof made
// with the upstream prover; see [cmdProve] for why the two aren't compatible.
func cmdVerify(dir string, upstream bool) error {
	publicWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("new witness: %w", err)
	}
	if err := readFrom(filepath.Join(dir, witnessFile), publicWitness); err != nil {
		return err
	}

	if upstream {
		vk := groth16.NewVerifyingKey(ecc.BN254)
		if err := readFrom(filepath.Join(dir, vkFile), vk); err != nil {
			return err
		}
		proof := groth16.NewProof(ecc.BN254)
		if err := readFrom(filepath.Join(dir, proofFile), proof); err != nil {
			return err
		}
		if err := groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
	} else {
		vk := new(bn254groth16.VerifyingKey)
		if err := readFrom(filepath.Join(dir, vkFile), vk); err != nil {
			return err
		}
		proof := new(bn254groth16.Proof)
		if err := readFrom(filepath.Join(dir, proofFile), proof); err != nil {
			return err
		}
		vector, ok := publicWitness.Vector().(fr.Vector)
		if !ok {
			return fmt.Errorf("unexpected public witness vector type %T", publicWitness.Vector())
		}
		if err := bn254groth16.Verify(proof, vk, vector, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
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

// exportSolidity writes the verifier contract using this repository's generator
// in backend/groth16/bn254 rather than gnark's. gnark's verifying key is
// re-read into the local one through its serialised form; the two types have
// the same layout, only the Solidity template and the commitment handling
// differ.
func exportSolidity(dir string, vk groth16.VerifyingKey) error {
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return fmt.Errorf("serialise verifying key: %w", err)
	}
	localVK := new(bn254groth16.VerifyingKey)
	if _, err := localVK.ReadFrom(&buf); err != nil {
		return fmt.Errorf("read verifying key into local backend: %w", err)
	}

	f, err := os.Create(filepath.Join(dir, solidityFile))
	if err != nil {
		return fmt.Errorf("create %s: %w", solidityFile, err)
	}
	defer f.Close()

	if err := localVK.ExportSolidity(f); err != nil {
		return fmt.Errorf("export solidity: %w", err)
	}
	fmt.Printf("wrote %s (%d public inputs, %d commitments)\n",
		filepath.Join(dir, solidityFile),
		len(localVK.G1.K)-1-len(localVK.PublicAndCommitmentCommitted),
		len(localVK.PublicAndCommitmentCommitted))
	return nil
}

// writeCalldata writes what a caller needs to hand the on-chain verifier: the
// proof in the packed form verifyProof expects, and the public inputs.
func writeCalldata(dir string, proof io.WriterTo, publicWitness witness.Witness) error {
	localProof, err := toLocalProof(proof)
	if err != nil {
		return err
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

	payload := struct {
		Proof  string   `json:"proof"`
		Inputs []string `json:"input"`
	}{
		Proof:  "0x" + hex.EncodeToString(localProof.MarshalSolidity()),
		Inputs: inputs,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
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

// toLocalProof re-reads a gnark proof into this repository's Proof type, which
// is the one that knows how to pack itself for the generated verifier.
func toLocalProof(proof io.WriterTo) (*bn254groth16.Proof, error) {
	if local, ok := proof.(*bn254groth16.Proof); ok {
		return local, nil
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("serialise proof: %w", err)
	}
	local := new(bn254groth16.Proof)
	if _, err := local.ReadFrom(&buf); err != nil {
		return nil, fmt.Errorf("read proof into local backend: %w", err)
	}
	return local, nil
}

// baseFromSeed returns the secret 𝔽p¹² base. An empty seed gives a random one,
// otherwise the twelve coefficients are derived from the seed so that a run can
// be reproduced.
func baseFromSeed(seed string) (*bn254.E12, error) {
	var base bn254.E12
	if seed == "" {
		if _, err := base.SetRandom(); err != nil {
			return nil, fmt.Errorf("random 𝔽p¹² element: %w", err)
		}
		return &base, nil
	}

	coeffs := []*bn254fp.Element{
		&base.C0.B0.A0, &base.C0.B0.A1, &base.C0.B1.A0, &base.C0.B1.A1,
		&base.C0.B2.A0, &base.C0.B2.A1, &base.C1.B0.A0, &base.C1.B0.A1,
		&base.C1.B1.A0, &base.C1.B1.A1, &base.C1.B2.A0, &base.C1.B2.A1,
	}
	digest := sha256.Sum256([]byte(seed))
	for _, c := range coeffs {
		digest = sha256.Sum256(digest[:])
		c.SetBytes(digest[:])
	}
	if base.IsZero() {
		return nil, fmt.Errorf("seed %q derives the zero element", seed)
	}
	return &base, nil
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
