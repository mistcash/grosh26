package ring_bn254

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"

	"github.com/mistcash/grosh26/internal/bench"
)

// BenchmarkPairingCheck compiles the two-pair check and reports the
// constraint count, so no caller has to hardcode one.
func BenchmarkPairingCheck(b *testing.B) {
	p1, p2, q1, q2 := randomPairingTriple(b)
	assignment := &pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckCircuit{} }, assignment)
}

// BenchmarkPairingCheckFixedQ is BenchmarkPairingCheck with the second pair's
// G2 point baked in via NewG2AffineFixed: the gap between the two counts is
// what the precomputed lines save.
func BenchmarkPairingCheckFixedQ(b *testing.B) {
	p1, p2, q1, q2 := randomPairingTriple(b)
	assignment := &pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckFixedQCircuit{q2: q2} }, assignment)
}
