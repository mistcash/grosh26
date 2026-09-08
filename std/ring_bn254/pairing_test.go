package ring_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
)

// randomPairingTriple returns [a]G1, [b]G2 and [-ab]G1, so that
// e([a]G1, [b]G2) · e([-ab]G1, G2) == 1.
func randomPairingTriple(t testing.TB) (p1, p2 bn254.G1Affine, q1, q2 bn254.G2Affine) {
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
	return pr.PairingCheck([]*G1Affine{&c.P1, &c.P2}, []*G2Affine{&c.Q1, &c.Q2}, nil)
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
	fixedQ2 := sw_bn254.NewG2AffineFixed(c.q2)
	return pr.PairingCheck(
		[]*G1Affine{&c.P1, &c.P2},
		[]*G2Affine{&c.Q1, &fixedQ2},
		nil,
	)
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

// TestFixedQPanicsOnBadPoint pins gnark's behavior: baking a G2 point in
// skips the in-circuit subgroup check, so NewG2AffineFixed panics
// off-circuit on a point outside the subgroup (surfaced as an error by
// test.IsSolved).
func TestFixedQPanicsOnBadPoint(t *testing.T) {
	p1, p2, q1, q2 := randomPairingTriple(t)
	assignment := &pairingCheckFixedQCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		P2: sw_bn254.NewG1Affine(p2),
		Q1: sw_bn254.NewG2Affine(q1),
	}

	offTwist := q2
	offTwist.X.A0.Add(&offTwist.X.A0, new(fp.Element).SetOne())

	assert := test.NewAssert(t)
	err := test.IsSolved(&pairingCheckFixedQCircuit{q2: offTwist}, assignment, ecc.BN254.ScalarField())
	assert.Error(err)
	assert.Contains(err.Error(), "not in the G2 subgroup")
}

// pairingCheckFixedCircuit fixes the second pair's points, so only P1, Q1
// run the ladder in-circuit.
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
	fixedP2 := sw_bn254.NewG1Affine(c.p2)
	fixedQ2 := sw_bn254.NewG2AffineFixed(c.q2)
	return pr.PairingCheck(
		[]*G1Affine{&c.P1, &fixedP2},
		[]*G2Affine{&c.Q1, &fixedQ2},
		nil,
	)
}

// TestPairingCheckFixedPair checks the same identity with the second pair's
// points baked in.
func TestPairingCheckFixedPair(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckFixedCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.NoError(test.IsSolved(&pairingCheckFixedCircuit{p2: p2, q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckFixedPairRejectsNonPairing makes sure the baked-in pair
// is a factor of the identity and not merely dropped.
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
// evaluates is the one the loop here uses and the one gnark's residue witness
// hint draws from.
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

// pairingCheckPreviousCircuit checks e(P1,Q1)·e(P2,Q2) == 1 with the second
// pair's Miller loop value passed directly as previous, like gnark's
// MultiMillerLoopAndFinalExpCircuit: the value never reaches the loop.
type pairingCheckPreviousCircuit struct {
	Prev sw_bn254.GTEl
	P1   sw_bn254.G1Affine
	Q1   sw_bn254.G2Affine
}

func (c *pairingCheckPreviousCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	return pr.PairingCheck(
		[]*G1Affine{&c.P1},
		[]*G2Affine{&c.Q1},
		&c.Prev,
	)
}

// previousMillerValue returns the raw Miller loop value e(p,q) off-circuit,
// in the MillerLoopFixedQ form the check compares against the residue.
func previousMillerValue(t testing.TB, p bn254.G1Affine, q bn254.G2Affine) bn254.GT {
	t.Helper()
	ml, err := millerValue(p, q)
	if err != nil {
		t.Fatal(err)
	}
	return ml
}

// millerValue is previousMillerValue without the testing dependency, for
// use inside Define.
func millerValue(p bn254.G1Affine, q bn254.G2Affine) (bn254.GT, error) {
	return bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{p},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(q)},
	)
}

// TestPairingCheckPrevious pins the previous-value path: the folded-in value
// is a factor of the identity and the check still has to hold.
func TestPairingCheckPrevious(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckPreviousCircuit{
		Prev: sw_bn254.NewGTEl(previousMillerValue(t, p2, q2)),
		P1:   sw_bn254.NewG1Affine(p1),
		Q1:   sw_bn254.NewG2Affine(q1),
	}
	assert.NoError(test.IsSolved(&pairingCheckPreviousCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestPairingCheckPreviousRejectsNonPairing makes sure the folded-in value
// is not merely dropped.
func TestPairingCheckPreviousRejectsNonPairing(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, q2 := randomPairingTriple(t)

	var p2 bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	p2.ScalarMultiplication(&g1, big.NewInt(42))

	assignment := &pairingCheckPreviousCircuit{
		Prev: sw_bn254.NewGTEl(previousMillerValue(t, p2, q2)),
		P1:   sw_bn254.NewG1Affine(p1),
		Q1:   sw_bn254.NewG2Affine(q1),
	}
	assert.Error(test.IsSolved(&pairingCheckPreviousCircuit{}, assignment, ecc.BN254.ScalarField()))
}

// pairingCheckPreviousConstCircuit bakes the previous value from native
// fixed points inside Define -- the verifier's shape -- so it travels as a
// compile-time constant rather than a witness.
type pairingCheckPreviousConstCircuit struct {
	P1 sw_bn254.G1Affine
	Q1 sw_bn254.G2Affine

	p2 bn254.G1Affine
	q2 bn254.G2Affine
}

func (c *pairingCheckPreviousConstCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	ml, err := millerValue(c.p2, c.q2)
	if err != nil {
		return err
	}
	prev := sw_bn254.NewGTEl(ml)
	return pr.PairingCheck(
		[]*G1Affine{&c.P1},
		[]*G2Affine{&c.Q1},
		&prev,
	)
}

// TestPairingCheckPreviousConst pins the verifier's shape: a previous value
// built from fixed points inside Define, travelling as a constant.
func TestPairingCheckPreviousConst(t *testing.T) {
	assert := test.NewAssert(t)
	p1, p2, q1, q2 := randomPairingTriple(t)

	assignment := &pairingCheckPreviousConstCircuit{
		P1: sw_bn254.NewG1Affine(p1),
		Q1: sw_bn254.NewG2Affine(q1),
	}
	assert.NoError(test.IsSolved(&pairingCheckPreviousConstCircuit{p2: p2, q2: q2}, assignment, ecc.BN254.ScalarField()))
}

// refused rather than silently zeroing the product: the hint rejects it.
func TestPairingCheckPreviousRejectsZero(t *testing.T) {
	assert := test.NewAssert(t)
	p1, _, q1, _ := randomPairingTriple(t)

	assignment := &pairingCheckPreviousCircuit{
		Prev: sw_bn254.NewGTEl(bn254.GT{}),
		P1:   sw_bn254.NewG1Affine(p1),
		Q1:   sw_bn254.NewG2Affine(q1),
	}
	err := test.IsSolved(&pairingCheckPreviousCircuit{}, assignment, ecc.BN254.ScalarField())
	assert.Error(err)
	assert.Contains(err.Error(), "zero")
}

// previousOnlyCircuit has nothing left for the Miller loop to run over.
type previousOnlyCircuit struct {
	Prev sw_bn254.GTEl
}

func (c *previousOnlyCircuit) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		return err
	}
	return pr.PairingCheck(nil, nil, &c.Prev)
}

// TestPairingCheckRejectsPreviousOnly makes sure a product of nothing but a
// previous value is refused rather than silently accepted: it constrains no
// witness, so a circuit asking for one is a mistake.
func TestPairingCheckRejectsPreviousOnly(t *testing.T) {
	assert := test.NewAssert(t)
	_, p2, _, q2 := randomPairingTriple(t)

	assignment := &previousOnlyCircuit{
		Prev: sw_bn254.NewGTEl(previousMillerValue(t, p2, q2)),
	}
	assert.Error(test.IsSolved(&previousOnlyCircuit{}, assignment, ecc.BN254.ScalarField()))
}
