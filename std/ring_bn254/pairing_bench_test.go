package ring_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"

	"github.com/mistcash/grosh26/lib/bench"
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
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckCircuit{} }, assignment, "pairingCheckCircuit")
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
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckPreviousCircuit{} }, assignment, "pairingCheckPreviousCircuit")
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
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckFixedQCircuit{q2: q2} }, assignment, "pairingCheckFixedQCircuit")
}

// BenchmarkThreePairingCheckGnark checks e(2p,q)·e(p,2q)·e(-pq,4G2) == 1
// with gnark's pairing: three plain pairs through the loop, no fixed points,
// no folded-in Miller loop value.
func BenchmarkThreePairingCheckGnark(b *testing.B) {
	p, pqNeg, q, g2 := randomPairingTriple(b)
	var p1, p2, p3 bn254.G1Affine
	var q1, q2, q3 bn254.G2Affine

	p1.Set(&p)
	q1.Set(&q)

	p2.Double(&p)
	q2.Double(&q)

	p3.Set(&pqNeg)
	q3.Set(&g2)
	q3.Double(&q3).Double(&q3)

	assignment := &ThreePairingCheckCircuitGnark{
		In1G1: sw_bn254.NewG1Affine(p2),      // 2p
		In1G2: sw_bn254.NewG2Affine(q),       // q
		In2G1: sw_bn254.NewG1Affine(p1),      // p
		In2G2: sw_bn254.NewG2AffineFixed(q2), // 2q
		In3G1: sw_bn254.NewG1Affine(p3),      // -pq
		In3G2: sw_bn254.NewG2AffineFixed(q3), // 4G2
	}
	bench.Circuit(b, func() frontend.Circuit {
		return &ThreePairingCheckCircuitGnark{
			In2G2: sw_bn254.NewG2AffineFixedPlaceholder(),
			In3G2: sw_bn254.NewG2AffineFixedPlaceholder(),
		}
	}, assignment, "threePairingCheckGnark")
}

// BenchmarkThreePairingCheck checks e(2p,q)·e(p,2q)·e(-pq,4G2) == 1 with the
// ring pairing: three plain pairs through the loop, no fixed points, no
// folded-in Miller loop value. The gap to BenchmarkThreePairingCheckGnark is
// what the ring Miller loop saves over gnark's on the same statement.
func BenchmarkThreePairingCheck(b *testing.B) {
	p, pqNeg, q, g2 := randomPairingTriple(b)
	var p1, p2, p3 bn254.G1Affine
	var q1, q2, q3 bn254.G2Affine

	p1.Set(&p)
	q1.Set(&q)

	p2.Double(&p)
	q2.Double(&q)

	p3.Set(&pqNeg)
	q3.Set(&g2)
	q3.Double(&q3).Double(&q3)

	assignment := &ThreePairingCheckCircuit{
		In1G1: sw_bn254.NewG1Affine(p2),      // 2p
		In1G2: sw_bn254.NewG2Affine(q),       // q
		In2G1: sw_bn254.NewG1Affine(p1),      // p
		In2G2: sw_bn254.NewG2AffineFixed(q2), // 2q
		In3G1: sw_bn254.NewG1Affine(p3),      // -pq
		In3G2: sw_bn254.NewG2AffineFixed(q3), // 4G2
	}
	bench.Circuit(b, func() frontend.Circuit {
		return &ThreePairingCheckCircuit{
			In2G2: sw_bn254.NewG2AffineFixedPlaceholder(),
			In3G2: sw_bn254.NewG2AffineFixedPlaceholder(),
		}
	}, assignment, "threePairingCheck")
}

// BenchmarkGroth16SimGnark checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 with gnark's pairing:
// γₙₑg and δₙₑg share one fixed G2 with precomputed lines, e(αₙₑg,β) is folded
// in as the previous Miller loop value, and kSum is recombined in-circuit as
// Public·K1 + K0. The count pins the combined saving of precomputed lines and
// the folded-in Miller loop.
func BenchmarkGroth16SimGnark(b *testing.B) {
	p, pqNeg, q, g2 := randomPairingTriple(b)
	var ar, krs bn254.G1Affine
	ar.Double(&p)
	krs.Double(&pqNeg)

	k0Pt, publicNative := scalarSplit(b, p, pqNeg)

	assignment := &groth16SimGnark{
		Ar:     sw_bn254.NewG1Affine(ar),
		Bs:     sw_bn254.NewG2Affine(q),
		Public: sw_bn254.NewScalar(publicNative),
		Krs:    sw_bn254.NewG1Affine(krs),
	}
	newCircuit := func() frontend.Circuit {
		fixed := sw_bn254.NewG2AffineFixed(g2)
		return &groth16SimGnark{
			GammaNeg:  fixed,
			DeltaNeg:  fixed,
			K1:        sw_bn254.NewG1Affine(p),
			K0:        sw_bn254.NewG1Affine(k0Pt),
			AlphaBeta: sw_bn254.NewGTEl(previousMillerValue(b, p, q)),
		}
	}
	bench.Circuit(b, newCircuit, assignment, "groth16SimGnark")
}

// BenchmarkGroth16Sim checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 with the ring pairing:
// γₙₑg and δₙₑg share one fixed G2 with precomputed lines, e(αₙₑg,β) is folded
// in as the previous Miller loop value, and kSum is recombined in-circuit as
// Public·K1 + K0. The count pins the combined saving of precomputed lines and
// the folded-in Miller loop.
func BenchmarkGroth16Sim(b *testing.B) {
	p, pqNeg, q, g2 := randomPairingTriple(b)
	var ar, krs bn254.G1Affine
	ar.Double(&p)
	krs.Double(&pqNeg)

	k0Pt, publicNative := scalarSplit(b, p, pqNeg)

	assignment := &groth16Sim{
		Ar:     sw_bn254.NewG1Affine(ar), // 2p
		Bs:     sw_bn254.NewG2Affine(q),  // q
		K1:     sw_bn254.NewG1Affine(p),  // K1, Public·K1 + K0 == -pq
		Public: sw_bn254.NewScalar(publicNative),
		K0:     sw_bn254.NewG1Affine(k0Pt),
		Krs:    sw_bn254.NewG1Affine(krs), // -2pq
	}
	newCircuit := func() frontend.Circuit {
		fixed := sw_bn254.NewG2AffineFixed(g2)
		return &groth16Sim{
			GammaNeg:  fixed,
			DeltaNeg:  fixed,
			K1:        sw_bn254.NewG1Affine(p),
			K0:        sw_bn254.NewG1Affine(k0Pt),
			AlphaBeta: sw_bn254.NewGTEl(previousMillerValue(b, p, q)),
		}
	}
	bench.Circuit(b, newCircuit, assignment, "groth16Sim")
}
