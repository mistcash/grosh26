package ring_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// randomPairingTriple returns [a]G1, [b]G2 and [-ab]G1, so that
// e([a]G1, [b]G2) · e([-ab]G1, G2) == 1.
func randomPairingTriple(t *testing.T) (p1, p2 bn254.G1Affine, q1, q2 bn254.G2Affine) {
	t.Helper()
	_, _, g1, g2 := bn254.Generators()

	var a, b fr.Element
	if _, err := a.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var negAB fr.Element
	negAB.Mul(&a, &b).Neg(&negAB)

	var aBig, bBig, negABBig big.Int
	a.BigInt(&aBig)
	b.BigInt(&bBig)
	negAB.BigInt(&negABBig)

	p1.ScalarMultiplication(&g1, &aBig)
	q1.ScalarMultiplication(&g2, &bBig)
	p2.ScalarMultiplication(&g1, &negABBig)
	q2 = g2
	return
}

type pairingCheckCircuit struct {
	P1, P2 sw_bn254.G1Affine
	Q1, Q2 sw_bn254.G2Affine
}

func (c *pairingCheckCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	pr.AssertIsOnG1(&c.P2)
	return pr.PairingCheck([]*G1Affine{&c.P1, &c.P2}, []*G2Affine{&c.Q1, &c.Q2})
}

func TestPairingCheck(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	assert.NoError(test.IsSolved(&pairingCheckCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckRejectsNonPairing makes sure the check is not vacuous.
func TestPairingCheckRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, q2 := randomPairingTriple(t)

	// p2 is now unrelated to p1, so the product of the two pairings is not one
	var p2 bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	p2.ScalarMultiplication(&g1, big.NewInt(42))

	assignment := &pairingCheckCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
		Q2: sw_bn254.NewG2Affine(q2),
	}
	assert.Error(test.IsSolved(&pairingCheckCircuit{}, assignment, ecc.BN254.ScalarField()))
}

type pairCircuit struct {
	P sw_bn254.G1Affine
	Q sw_bn254.G2Affine
	R sw_bn254.GTEl
}

func (c *pairCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pr.Pair([]*G1Affine{&c.P}, []*G2Affine{&c.Q})
	if err != nil {
		return err
	}
	pr.AssertIsEqual(res, &c.R)
	return nil
}

// TestPair pins the ring Miller loop against gnark-crypto's pairing.
func TestPair(t *testing.T) {
	assert := test.NewAssert(t)
	p, _, q, _ := randomPairingTriple(t)

	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)

	assignment := &pairCircuit{
		P: sw_bn254.NewG1Affine(p),
		Q: sw_bn254.NewG2Affine(q),
		R: sw_bn254.NewGTEl(res),
	}
	assert.NoError(test.IsSolved(&pairCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// pairingCheckFixedQCircuit is [pairingCheckCircuit] with Q2 fixed when the
// circuit is built rather than taken from the witness: its line evaluations
// are precomputed off-circuit, so only Q1 runs the ladder in-circuit.
//
// q2 is a Go-level field, not a witness variable -- the same shape
// std/recursion's Circuit gives its verifying key -- so the unassigned
// circuit passed to the compiler has to carry it.
type pairingCheckFixedQCircuit struct {
	P1, P2 sw_bn254.G1Affine
	Q1     sw_bn254.G2Affine

	q2 bn254.G2Affine
}

func (c *pairingCheckFixedQCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	pr.AssertIsOnG1(&c.P2)
	fixedQ, err := pr.NewFixedQPair(&c.P2, c.q2)
	if err != nil {
		return err
	}
	return pr.PairingCheckPairs(NewPair(&c.P1, &c.Q1), fixedQ)
}

// TestPairingCheckFixedQ checks the same e(P1,Q1)·e(P2,Q2) == 1 statement as
// [TestPairingCheck], with the second pair's G2 point baked in.
func TestPairingCheckFixedQ(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.NoError(test.IsSolved(&pairingCheckFixedQCircuit{q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckFixedQRejectsNonPairing makes sure precomputing the lines
// did not make the check vacuous.
func TestPairingCheckFixedQRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, q2 := randomPairingTriple(t)

	// p2 is now unrelated to p1, so the product of the two pairings is not one
	var p2 bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	p2.ScalarMultiplication(&g1, big.NewInt(42))

	assignment := &pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.Error(test.IsSolved(&pairingCheckFixedQCircuit{q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// TestFixedQPairRejectsBadPoint makes sure baking a G2 point in does not lose
// the subgroup check that computing its lines in-circuit would have run: with
// no ladder left in the circuit, nothing downstream would catch a point off
// the twist or at infinity, so NewFixedQPair has to.
func TestFixedQPairRejectsBadPoint(t *testing.T) {
	p1, p2, q1, q2 := randomPairingTriple(t)
	assignment := &pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}

	offTwist := q2
	offTwist.X.A0.Add(&offTwist.X.A0, new(fp.Element).SetOne())

	for name, bad := range map[string]struct {
		q      bn254.G2Affine
		reason string
	}{
		"off the twist": {offTwist, "not in the prime-order subgroup"},
		"infinity":      {bn254.G2Affine{}, "point at infinity"},
	} {
		t.Run(name, func(t *testing.T) {
			assert := test.NewAssert(t)
			err := test.IsSolved(&pairingCheckFixedQCircuit{q2: bad.q}, assignment, ecc.BN254.ScalarField())
			assert.Error(err)
			assert.Contains(err.Error(), bad.reason,
				"a bad fixed point has to be rejected as such, not caught incidentally")
		})
	}
}

// pairingCheckFixedCircuit fixes the whole second pair, so its Miller loop
// value is a compile-time constant and only P1, Q1 reach the loop.
type pairingCheckFixedCircuit struct {
	P1 sw_bn254.G1Affine
	Q1 sw_bn254.G2Affine

	p2 bn254.G1Affine
	q2 bn254.G2Affine
}

func (c *pairingCheckFixedCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	fixed, err := pr.NewFixedPair(c.p2, c.q2)
	if err != nil {
		return err
	}
	return pr.PairingCheckPairs(NewPair(&c.P1, &c.Q1), fixed)
}

// TestPairingCheckFixedPair pins the constant-factor path: e(P2,Q2) never
// reaches the Miller loop, it is folded in as one precomputed 𝔽p¹² factor,
// and the identity still has to hold.
func TestPairingCheckFixedPair(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckFixedCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.NoError(test.IsSolved(&pairingCheckFixedCircuit{p2: p2, q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckFixedPairRejectsNonPairing makes sure the folded-in
// constant is a factor of the identity and not merely dropped.
func TestPairingCheckFixedPairRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, q2 := randomPairingTriple(t)

	var p2 bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	p2.ScalarMultiplication(&g1, big.NewInt(42))

	assignment := &pairingCheckFixedCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.Error(test.IsSolved(&pairingCheckFixedCircuit{p2: p2, q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// allFixedCircuit has nothing left in the witness for the Miller loop to run
// over.
type allFixedCircuit struct {
	Unused sw_bn254.G1Affine

	p, p2 bn254.G1Affine
	q, q2 bn254.G2Affine
}

func (c *allFixedCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	first, err := pr.NewFixedPair(c.p, c.q)
	if err != nil {
		return err
	}
	second, err := pr.NewFixedPair(c.p2, c.q2)
	if err != nil {
		return err
	}
	return pr.PairingCheckPairs(first, second)
}

// TestPairingCheckPairsRejectsAllFixed makes sure a product of nothing but
// constants is refused rather than silently accepted: it constrains no
// witness, so a circuit asking for one is a mistake.
func TestPairingCheckPairsRejectsAllFixed(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	circuit := &allFixedCircuit{p: p1, q: q1, p2: p2, q2: q2}
	assert.Error(test.IsSolved(circuit, &allFixedCircuit{}, ecc.BN254.ScalarField()))
}

type millerLoopCircuit struct {
	P sw_bn254.G1Affine
	Q sw_bn254.G2Affine
	R sw_bn254.GTEl
}

func (c *millerLoopCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pr.MillerLoop([]*G1Affine{&c.P}, []*G2Affine{&c.Q})
	if err != nil {
		return err
	}
	pr.AssertIsEqual(res, &c.R)
	return nil
}

// TestMillerLoopMatchesFixedQ pins the raw Miller loop value -- not just the
// reduced pairing [TestPair] covers -- against gnark-crypto's
// MillerLoopFixedQ.
//
// Which of gnark-crypto's two Miller loops it matches is not incidental.
// bn254.MillerLoop runs the ladder in projective coordinates and its raw
// value carries the lines' Z factors; they die in the final exponentiation,
// but this package never runs one. The affine line form MillerLoopFixedQ
// evaluates is the one the loop here uses, the one gnark's residue witness
// hint draws from, and the one [Pairing.NewFixedPair] bakes in as a constant.
func TestMillerLoopMatchesFixedQ(t *testing.T) {
	assert := test.NewAssert(t)
	p, _, q, _ := randomPairingTriple(t)

	res, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(q)},
	)
	assert.NoError(err)

	assignment := &millerLoopCircuit{
		P: sw_bn254.NewG1Affine(p),
		Q: sw_bn254.NewG2Affine(q),
		R: sw_bn254.NewGTEl(res),
	}
	assert.NoError(test.IsSolved(&millerLoopCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestFixedQSavesConstraints compiles the same e(P1,Q1)·e(P2,Q2) == 1 check
// twice, once with both G2 points from the witness and once with Q2 fixed.
// The two circuits differ only in Q2's [6x₀+2]Q ladder and subgroup check, so
// the gap is what precomputing one G2 point's lines is worth -- the saving
// std/recursion's Groth16 verifier collects twice, for γ and δ.
func TestFixedQSavesConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the pairing circuit compilations under -short")
	}
	_, _, _, q2 := randomPairingTriple(t)

	variable, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairingCheckCircuit{})
	require.NoError(t, err)
	fixed, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pairingCheckFixedQCircuit{q2: q2})
	require.NoError(t, err)

	nbVariable, nbFixed := variable.GetNbConstraints(), fixed.GetNbConstraints()
	t.Logf("two-pair check: %d constraints with both Q from the witness, %d with one fixed (%.1f%% fewer)",
		nbVariable, nbFixed, 100*float64(nbVariable-nbFixed)/float64(nbVariable))

	// the ladder and the subgroup check are a large fraction of a pair's
	// cost, so the saving is tens of percent, not a rounding error. Pinned
	// loosely: the point is that fixing Q removes work, not the exact figure,
	// which moves with every gnark release.
	require.Less(t, nbFixed, nbVariable*4/5, "fixing one of two G2 points should cut the check by more than a fifth")
}
