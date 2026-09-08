package recursion_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/mistcash/grosh26/internal/bench"
	"github.com/mistcash/grosh26/std/recursion"
)

// BenchmarkOuterCircuit compiles the end-to-end Groth16-in-Groth16 verifier
// and reports the constraint count, so no doc has to hardcode one. Run with
// -benchtime=1x, a single pass already takes seconds at this size.
func BenchmarkOuterCircuit(b *testing.B) {
	fx := newInnerFixture(b)
	outerVK, err := recursion.NewVerifyingKey(fx.vk)
	if err != nil {
		b.Fatal(err)
	}
	_, assignment := fx.circuit(b, fx.vk, fx.proof, fx.public)
	bench.Circuit(b, func() frontend.Circuit { return recursion.NewCircuit(outerVK) }, assignment)
}
