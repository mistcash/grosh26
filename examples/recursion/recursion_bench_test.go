package recursion_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/mistcash/grosh26/std/recursion"
)

// BenchmarkOuterCircuit compiles the end-to-end Groth16-in-Groth16 verifier
// and reports the constraint count, so no doc has to hardcode one. The
// prove-side cost is measured by the solve sub-benchmark; run with
// -benchtime=1x, a single pass already takes seconds at this size.
func BenchmarkOuterCircuit(b *testing.B) {
	fx := newInnerFixture(b)
	outerVK, err := recursion.NewVerifyingKey(fx.vk)
	if err != nil {
		b.Fatal(err)
	}
	_, assignment := fx.circuit(b, fx.vk, fx.proof, fx.public)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(outerVK)); err != nil {
				b.Fatal(err)
			}
		}
	})
	var buf bytes.Buffer
	if _, err = ccs.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	b.Logf("r1cs size: %d (bytes), nb constraints %d", buf.Len(), ccs.GetNbConstraints())
	b.Run("solve", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
}
