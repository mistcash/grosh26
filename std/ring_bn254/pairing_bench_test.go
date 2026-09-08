package ring_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
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

// BenchmarkPairingCheckPrevious is BenchmarkPairingCheck with one pair's
// Miller loop value passed directly as previous: the gap to the plain check
// is what folding the constant saves over running it through the loop.
func BenchmarkPairingCheckPrevious(b *testing.B) {
	p1, p2, q1, q2 := randomPairingTriple(b)
	assignment := &pairingCheckPreviousCircuit{
		Prev: sw_bn254.NewGTEl(previousMillerValue(b, p2, q2)),
		P1:   sw_bn254.NewG1Affine(p1),
		Q1:   sw_bn254.NewG2Affine(q1),
	}
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckPreviousCircuit{} }, assignment)
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

// BenchmarkThreePairingFixedPrev is the three-pairing check with two fixed-Q
// pairs sharing one G2 point in the loop and a fourth folded in as previous:
// the count pins the combined saving of precomputed lines and the folded-in
// Miller loop.
func BenchmarkThreePairingFixedPrev(b *testing.B) {
	p, pqNeg, q, g2 := randomPairingTriple(b)
	var p1, p2, p3 bn254.G1Affine
	p1.Double(&p)
	p2.Set(&pqNeg)
	p3.Double(&pqNeg)

	assignment := &groth16Sim{
		P1:   sw_bn254.NewG1Affine(p1),
		Q1:   sw_bn254.NewG2Affine(q),
		P2:   sw_bn254.NewG1Affine(p2),
		Q2:   sw_bn254.NewG2AffineFixed(g2),
		P3:   sw_bn254.NewG1Affine(p3),
		Q3:   sw_bn254.NewG2AffineFixed(g2),
		Prev: sw_bn254.NewGTEl(previousMillerValue(b, p, q)),
	}
	newCircuit := func() frontend.Circuit {
		fixed := sw_bn254.NewG2AffineFixed(g2)
		return &groth16Sim{Q2: fixed, Q3: fixed}
	}
	bench.Circuit(b, newCircuit, assignment)
}
