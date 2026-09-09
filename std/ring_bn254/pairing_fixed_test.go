package ring_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type ThreePairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In3G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
	In3G2 G2Affine
}

func (c *ThreePairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	return pairing.PairingCheck(
		[]*G1Affine{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*G2Affine{&c.In1G2, &c.In2G2, &c.In3G2},
		nil,
	)
}

// ThreePairingCheckCircuitGnark is ThreePairingCheckCircuit with gnark's
// pairing: the same e(2p,q)·e(p,2q)·e(-pq,4G2) == 1 statement, so the gap
// between the two counts is what the ring Miller loop saves over gnark's.
type ThreePairingCheckCircuitGnark struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In3G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
	In3G2 G2Affine
}

func (c *ThreePairingCheckCircuitGnark) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	return pairing.PairingCheck(
		[]*G1Affine{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*G2Affine{&c.In1G2, &c.In2G2, &c.In3G2},
	)
}

func TestThreePairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(2a, 2b) * e(-2a, b) * e(a, -2b) == 1
	p, pqNeg, q, g2 := randomPairingTriple(t)
	var p1, p2, p3 bn254.G1Affine
	var q1, q2, q3 bn254.G2Affine

	p1.Set(&p)
	q1.Set(&q)

	p2.Double(&p)
	q2.Double(&q)

	p3.Set(&pqNeg)
	q3.Set(&g2)
	q3.Double(&q3).Double(&q3)

	witness := ThreePairingCheckCircuit{
		In1G1: sw_bn254.NewG1Affine(p2), // 2p
		In1G2: sw_bn254.NewG2Affine(q),  // q
		In2G1: sw_bn254.NewG1Affine(p1), // p
		In2G2: sw_bn254.NewG2Affine(q2), // 2q
		In3G1: sw_bn254.NewG1Affine(p3), // -pq
		In3G2: sw_bn254.NewG2Affine(q3), // 4
	}
	err := test.IsSolved(&ThreePairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// scalarSplit draws a random scalar s and returns b = f - s·a, so the
// circuit can recombine f in-circuit as s·a + b.
func scalarSplit(t testing.TB, a, f bn254.G1Affine) (b bn254.G1Affine, s fr.Element) {
	t.Helper()
	if _, err := s.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var sBig big.Int
	s.BigInt(&sBig)
	var sA bn254.G1Affine
	sA.ScalarMultiplication(&a, &sBig)
	b.Sub(&f, &sA)
	return b, s
}

// groth16Sim checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 with three pairs
// in the loop and e(αₙₑg,β) folded in as a previous Miller loop value. GammaNeg
// and DeltaNeg are the same G2 point carrying precomputed lines, so their ladders
// and subgroup checks never enter the circuit. The kSum point is
// recombined in-circuit as Public·K1 + K0 from two witness points and a scalar.
type groth16SimGnark struct {
	// verifiying key
	K0, K1             sw_bn254.G1Affine `gnark:"-"`
	GammaNeg, DeltaNeg sw_bn254.G2Affine `gnark:"-"`
	AlphaBeta          sw_bn254.GTEl     `gnark:"-"`
	// proof
	Ar, Krs sw_bn254.G1Affine
	Public  sw_bn254.Scalar
	Bs      sw_bn254.G2Affine
}

func (c *groth16SimGnark) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	pairing.AssertIsOnG1(&c.Ar)
	pairing.AssertIsOnG1(&c.Krs)
	kSum := curve.AddUnified(curve.ScalarMul(&c.K1, &c.Public), &c.K0)
	pairing.AssertMultiMillerLoopAndFinalExpIsOne(
		[]*G1Affine{&c.Ar, kSum, &c.Krs},
		[]*G2Affine{&c.Bs, &c.GammaNeg, &c.DeltaNeg},
		&c.AlphaBeta,
	)
	return nil
}

// groth16Sim checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 with three pairs
// in the loop and e(αₙₑg,β) folded in as a previous Miller loop value. GammaNeg
// and DeltaNeg are the same G2 point carrying precomputed lines, so their ladders
// and subgroup checks never enter the circuit. The kSum point is
// recombined in-circuit as Public·K1 + K0 from two witness points and a scalar.
type groth16Sim struct {
	// verifiying key
	K0, K1             sw_bn254.G1Affine `gnark:"-"`
	GammaNeg, DeltaNeg sw_bn254.G2Affine `gnark:"-"`
	AlphaBeta          sw_bn254.GTEl     `gnark:"-"`
	// proof
	Ar, Krs sw_bn254.G1Affine
	Public  sw_bn254.Scalar
	Bs      sw_bn254.G2Affine
}

func (c *groth16Sim) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	pairing.AssertIsOnG1(&c.Ar)
	pairing.AssertIsOnG1(&c.Krs)
	kSum := curve.AddUnified(curve.ScalarMul(&c.K1, &c.Public), &c.K0)
	return pairing.PairingCheck(
		[]*G1Affine{&c.Ar, kSum, &c.Krs},
		[]*G2Affine{&c.Bs, &c.GammaNeg, &c.DeltaNeg},
		&c.AlphaBeta,
	)
}

func TestGroth16Sim(t *testing.T) {
	assert := test.NewAssert(t)
	// e(Ar, Bs) * e(kSum, γₙₑg) * e(Krs, δₙₑg) * e(αₙₑg, β) == 1 with kSum ==
	// -pq recombined in-circuit as Public·K1 + K0: γₙₑg and δₙₑg share one
	// fixed G2 with precomputed lines, e(αₙₑg, β) is folded in as the
	// previous Miller loop value instead of a pass through the loop.
	p, pqNeg, q, g2 := randomPairingTriple(t)
	var ar, krs bn254.G1Affine
	ar.Double(&p)
	krs.Double(&pqNeg)

	k0Pt, publicNative := scalarSplit(t, p, pqNeg)

	fixed := sw_bn254.NewG2AffineFixed(g2)
	unassigned := &groth16Sim{
		GammaNeg: fixed,
		DeltaNeg: fixed,
		K1:       sw_bn254.NewG1Affine(p), K0: sw_bn254.NewG1Affine(k0Pt),
		AlphaBeta: sw_bn254.NewGTEl(previousMillerValue(t, p, q)),
	}
	assignment := &groth16Sim{
		Ar:     sw_bn254.NewG1Affine(ar), // 2p
		Bs:     sw_bn254.NewG2Affine(q),  // q
		K1:     sw_bn254.NewG1Affine(p),  // K1, Public·K1 + K0 == -pq
		Public: sw_bn254.NewScalar(publicNative),
		K0:     sw_bn254.NewG1Affine(k0Pt),
		Krs:    sw_bn254.NewG1Affine(krs), // -2pq
	}
	err := test.IsSolved(unassigned, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
