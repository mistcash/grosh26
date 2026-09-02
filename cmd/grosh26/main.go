// Command grosh26 drives the recursive proof end to end: it sets up the inner
// (poseidon) and outer (Groth16-verifier) circuits, proves the inner circuit
// then the outer circuit over that proof, verifies the outer proof off-chain,
// and generates the Solidity verifier and calldata for the outer proof.
//
//	grosh26 setup      compile both circuits, run their Groth16 setups, write
//	                   the keys and export the outer Solidity verifier
//	grosh26 prove      prove the inner circuit, then the outer circuit over
//	                   that proof; write the outer proof, its public inputs
//	                   and the verifier calldata
//	grosh26 verify     verify the outer proof against the outer verifying key
//	grosh26 solidity   regenerate the outer Solidity verifier from its
//	                   verifying key
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "grosh26:", err)
		os.Exit(1)
	}
}

const usage = `usage: grosh26 <command> [-dir <artifacts>]

commands:
  setup      compile the inner and outer circuits, run their Groth16 setups,
             write the keys and export the outer Solidity verifier
  prove      prove the inner circuit, then the outer circuit over that proof;
             write the outer proof, its public inputs and the verifier
             calldata
  verify     verify the outer proof against the outer verifying key
  solidity   regenerate the outer Solidity verifier from its verifying key
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
