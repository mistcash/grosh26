// Package bench provides a generic compile-and-solve benchmark for gnark
// circuits on BN254 (r1cs), in the shape of gnark's BenchmarkPairing: compile
// the circuit, log the size and constraint count, then benchmark solving.
package bench

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit compiles newCircuit (r1cs, BN254), logs the size and constraint
// count, then benchmarks solving with assignment's witness. A solve failure
// fails the benchmark, so this also checks the circuit is satisfied.
//
// newCircuit is a factory, not a single value: compiling the same object
// twice is unsound for circuits that cache api-bound state in Define (this
// repo's pairing does, via Q.Lines, exactly like gnark's own), so the helper
// asks for a fresh template every iteration.
func Circuit(b *testing.B, newCircuit func() frontend.Circuit, assignment frontend.Circuit, circuitName string) {
	b.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile_"+circuitName, func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newCircuit()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("solve_"+circuitName, func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
	LogCircuitConstraints(b, newCircuit(), assignment, circuitName)
}

// LogCircuitConstraints prints the number of constraints and the size of the compiled circuit.
func LogCircuitConstraints(b testing.TB, newCircuit frontend.Circuit, assignment frontend.Circuit, circuitName string) {
	b.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newCircuit)
	if err != nil {
		b.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = ccs.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	b.Logf("%-22s r1cs constraints %10d size: %10d (bytes)", circuitName, ccs.GetNbConstraints(), buf.Len())
}
