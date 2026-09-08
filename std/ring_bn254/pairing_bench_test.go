package ring_bn254

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// BenchmarkPairingCheck mirrors gnark's BenchmarkPairing: it compiles the
// two-pair check and reports the constraint count, so no caller has to
// hardcode one.
func BenchmarkPairingCheck(b *testing.B) {
	p1, p2, q1, q2 := randomPairingTriple(b)
	witness := pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairingCheckCircuit{}); err != nil {
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

// BenchmarkPairingCheckFixedQ is BenchmarkPairingCheck with the second pair's
// G2 point baked in via NewG2AffineFixed: the gap between the two counts is
// what the precomputed lines save.
func BenchmarkPairingCheckFixedQ(b *testing.B) {
	p1, p2, q1, q2 := randomPairingTriple(b)
	witness := pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairingCheckFixedQCircuit{q2: q2}); err != nil {
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
