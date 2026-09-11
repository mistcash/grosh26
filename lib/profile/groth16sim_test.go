package profile

// Groth16-simulation benchmark: one bench function covering both pairing
// backends. Solving is part of the benchmark, so an unsatisfied statement
// fails it: this doubles as the solved test. Native point helpers are fixed,
// not random: counts never depended on the values and fixed points keep the
// profiles deterministic.

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkprofile "github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/grosh26/lib/bench"
	"github.com/mistcash/grosh26/std/ring_bn254"
)

// fixedTriple returns [2]G1, [-6]G1, [3]G2 and G2, so that
// e([2]G1, [3]G2) · e([-6]G1, G2) == 1.
func fixedTriple() (p, pqNeg bn254.G1Affine, q, g2 bn254.G2Affine) {
	_, _, g1, g2gen := bn254.Generators()
	p.ScalarMultiplication(&g1, big.NewInt(2))
	q.ScalarMultiplication(&g2gen, big.NewInt(3))
	var six bn254.G1Affine
	six.ScalarMultiplication(&g1, big.NewInt(6))
	pqNeg.Neg(&six)
	g2 = g2gen
	return
}

// scalarSplit returns b = f - a, so the circuit can recombine f in-circuit
// as Public·K1 + K0 with Public == 1.
func scalarSplit(a, f bn254.G1Affine) (b bn254.G1Affine, s fr.Element) {
	s.SetUint64(1)
	var sA bn254.G1Affine
	sA.ScalarMultiplication(&a, big.NewInt(1))
	b.Sub(&f, &sA)
	return b, s
}

// previousMillerValue returns the raw Miller loop value e(p,q) off-circuit,
// in the MillerLoopFixedQ form the check compares against the residue.
func previousMillerValue(p bn254.G1Affine, q bn254.G2Affine) bn254.GT {
	ml, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(q)},
	)
	if err != nil {
		panic(err)
	}
	return ml
}

// simPoints is one satisfying Groth16-simulation instance: Ar == 2p,
// Krs == -2pq and kSum recombines in-circuit as Public·K1 + K0, so K1, K0
// and Public are drawn together here and shared by both backends.
type simPoints struct {
	p, ar, krs, k0Pt bn254.G1Affine
	q, g2            bn254.G2Affine
	pub              fr.Element
}

func newSimPoints() simPoints {
	p, pqNeg, q, g2 := fixedTriple()
	var ar, krs bn254.G1Affine
	ar.Double(&p)
	krs.Double(&pqNeg)
	k0Pt, pub := scalarSplit(p, pqNeg)
	return simPoints{p: p, ar: ar, krs: krs, k0Pt: k0Pt, q: q, g2: g2, pub: pub}
}

// profileOnce compiles template under a gnark constraint-profile session,
// writing <dir>/<name>.pprof for the call-site PDFs. It writes nothing
// unless GNARK_PROFILE_DIR is set, so plain bench runs stay artifact-free.
func profileOnce(b *testing.B, name string, template frontend.Circuit) {
	b.Helper()
	dir := os.Getenv("GNARK_PROFILE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, name+".pprof")
	prof := gnarkprofile.Start(gnarkprofile.WithPath(path))
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		prof.Stop()
		b.Fatal(err)
	}
	prof.Stop()
	b.Logf("[%s] profiled %d constraints", name, ccs.GetNbConstraints())
}

// ksumOnlyCircuit isolates the Public·K1 + K0 recombination both backends
// run. No terminal assert: emulated ops emit constraints eagerly, so the
// bare Define counts exactly the recombination.
type ksumOnlyCircuit struct {
	K0, K1 G1Affine
	Public sw_bn254.Scalar
}

func (c *ksumOnlyCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	_ = curve.AddUnified(curve.ScalarMul(&c.K1, &c.Public), &c.K0)
	return nil
}

// g1ChecksOnlyCircuit isolates the two AssertIsOnG1 both backends run;
// both call gnark's check, so one measurement serves both columns.
type g1ChecksOnlyCircuit struct {
	Ar, Krs G1Affine
}

func (c *g1ChecksOnlyCircuit) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	pairing.AssertIsOnG1(&c.Ar)
	pairing.AssertIsOnG1(&c.Krs)
	return nil
}

// logConstraintProfile prints the per-phase constraint breakdown of the
// groth16Sim pair: shared phases measured once, backend-specific phases
// differenced from templates that vary in exactly one phase. Counts depend
// on circuit shape only, not on point values.
func logConstraintProfile(b *testing.B, sp simPoints) {
	b.Helper()
	count := func(c frontend.Circuit) int {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			b.Fatal(err)
		}
		return ccs.GetNbConstraints()
	}

	fixed := sw_bn254.NewG2AffineFixed(sp.g2)
	prev := sw_bn254.NewGTEl(previousMillerValue(sp.p, sp.q))
	k1 := sw_bn254.NewG1Affine(sp.p)
	k0 := sw_bn254.NewG1Affine(sp.k0Pt)

	fullRing := &groth16Sim{GammaNeg: fixed, DeltaNeg: fixed, K1: k1, K0: k0, AlphaBeta: prev}
	fullGnark := &groth16SimGnark{GammaNeg: fixed, DeltaNeg: fixed, K1: k1, K0: k0, AlphaBeta: prev}
	bsQ := sw_bn254.NewG2AffineFixed(sp.q)
	bsFixedRing := &groth16Sim{Bs: bsQ, GammaNeg: fixed, DeltaNeg: fixed, K1: k1, K0: k0, AlphaBeta: prev}
	bsFixedGnark := &groth16SimGnark{Bs: bsQ, GammaNeg: fixed, DeltaNeg: fixed, K1: k1, K0: k0, AlphaBeta: prev}

	totalRing := count(fullRing)
	totalGnark := count(fullGnark)
	ksum := count(&ksumOnlyCircuit{})
	g1checks := count(&g1ChecksOnlyCircuit{})
	ladderRing := totalRing - count(bsFixedRing)
	ladderGnark := totalGnark - count(bsFixedGnark)
	// Miller accumulation, final-exp tail and the folded-in previous value
	// as one unit: isolating the loop standalone would change the
	// computation (seeding, batching), so whatever the phases above do not
	// account for lands here.
	tailRing := totalRing - ksum - g1checks - ladderRing
	tailGnark := totalGnark - ksum - g1checks - ladderGnark

	b.Logf("constraint profile (r1cs, BN254):")
	b.Logf("%-22s %10s %10s %10s", "phase", "gnark", "ring", "delta")
	b.Logf("%-22s %10d %10d %10d", "total", totalGnark, totalRing, totalGnark-totalRing)
	b.Logf("%-22s %10d %10d %10d", "kSum recomb (shared)", ksum, ksum, 0)
	b.Logf("%-22s %10d %10d %10d", "G1 checks x2 (shared)", g1checks, g1checks, 0)
	b.Logf("%-22s %10d %10d %10d", "Bs ladder+subgroup", ladderGnark, ladderRing, ladderGnark-ladderRing)
	b.Logf("%-22s %10d %10d %10d", "loop+tail+previous", tailGnark, tailRing, tailGnark-tailRing)
}

// Point types are the ring package's gnark aliases; the circuits below only
// differ in which Miller loop they run.
type (
	G1Affine = ring_bn254.G1Affine
	G2Affine = ring_bn254.G2Affine
)

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

// groth16Sim is groth16SimGnark with the ring pairing; same statement.
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
	pairing, err := ring_bn254.NewPairing(api)
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

// BenchmarkGroth16Sim checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 with Bs variable,
// γₙₑg and δₙₑg sharing one fixed G2, e(αₙₑg,β) folded in as the previous
// Miller loop value and kSum recombined in-circuit as Public·K1 + K0 — once
// with gnark's pairing, once with the ring pairing.
func BenchmarkGroth16Sim(b *testing.B) {
	sp := newSimPoints()
	logConstraintProfile(b, sp)

	assignmentGnark := &groth16SimGnark{
		Ar:     sw_bn254.NewG1Affine(sp.ar),
		Bs:     sw_bn254.NewG2Affine(sp.q),
		Public: sw_bn254.NewScalar(sp.pub),
		Krs:    sw_bn254.NewG1Affine(sp.krs),
	}
	newCircuitGnark := func() frontend.Circuit {
		fixed := sw_bn254.NewG2AffineFixed(sp.g2)
		return &groth16SimGnark{
			GammaNeg:  fixed,
			DeltaNeg:  fixed,
			K1:        sw_bn254.NewG1Affine(sp.p),
			K0:        sw_bn254.NewG1Affine(sp.k0Pt),
			AlphaBeta: sw_bn254.NewGTEl(previousMillerValue(sp.p, sp.q)),
		}
	}
	profileOnce(b, "groth16sim-gnark", newCircuitGnark())
	bench.Circuit(b, newCircuitGnark, assignmentGnark, "groth16SimGnark")

	assignment := &groth16Sim{
		Ar:     sw_bn254.NewG1Affine(sp.ar), // 2p
		Bs:     sw_bn254.NewG2Affine(sp.q),  // q
		Public: sw_bn254.NewScalar(sp.pub),
		Krs:    sw_bn254.NewG1Affine(sp.krs), // -2pq
	}
	newCircuit := func() frontend.Circuit {
		fixed := sw_bn254.NewG2AffineFixed(sp.g2)
		return &groth16Sim{
			GammaNeg:  fixed,
			DeltaNeg:  fixed,
			K1:        sw_bn254.NewG1Affine(sp.p),
			K0:        sw_bn254.NewG1Affine(sp.k0Pt),
			AlphaBeta: sw_bn254.NewGTEl(previousMillerValue(sp.p, sp.q)),
		}
	}
	profileOnce(b, "groth16sim-ring", newCircuit())
	bench.Circuit(b, newCircuit, assignment, "groth16Sim")
}
