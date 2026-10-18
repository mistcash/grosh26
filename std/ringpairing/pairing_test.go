package ringpairing_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"

	"github.com/mistcash/grosh26/lib/bench"
	"github.com/mistcash/grosh26/std/ring_bls12381"
	"github.com/mistcash/grosh26/std/ring_bn254"
	"github.com/mistcash/grosh26/std/ringpairing"
)

// fixture is one curve's satisfying instance e(P1,Q1)·e(P2,Q2) == 1, with
// P1 = [a]G1, Q1 = [b]G2, P2 = [-ab]G1 and Q2 = G2, as circuit values.
// Constants baked into a circuit travel as native values and are built inside
// Define (see fixedG2 and gtEl), so every compile gets fresh ones.
type fixture[F emulated.FieldParams, G2El, GtEl any] struct {
	p1, p2, bad ringpairing.G1Affine[F] // bad = [42]G1, unrelated to P1
	q1, q2      G2El
	nativeQ2    any  // Q2 natively, for baking in with fixedG2
	offTwistQ2  any  // a native G2 point off the twist
	prev        GtEl // previous-value form of e(P2,Q2)
	nativePrev  any  // prev natively, for baking in with gtEl
	badPrev     GtEl // previous-value form of e(bad,Q2)
	zero        GtEl
	millerLoop  GtEl // MillerLoopFixedQ(P1, Q1)
	pair        GtEl // e(P1, Q1)
}

func randomScalars(t testing.TB, mod *big.Int) (a, b, negAB *big.Int) {
	t.Helper()
	var err error
	if a, err = rand.Int(rand.Reader, mod); err != nil {
		t.Fatal(err)
	}
	if b, err = rand.Int(rand.Reader, mod); err != nil {
		t.Fatal(err)
	}
	negAB = new(big.Int).Mul(a, b)
	negAB.Neg(negAB).Mod(negAB, mod)
	return a, b, negAB
}

func bn254Fixture(t testing.TB) fixture[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl] {
	_, _, g1, g2 := bn254.Generators()
	a, b, negAB := randomScalars(t, bnfr.Modulus())
	var p1, p2, bad bn254.G1Affine
	var q1 bn254.G2Affine
	p1.ScalarMultiplication(&g1, a)
	p2.ScalarMultiplication(&g1, negAB)
	bad.ScalarMultiplication(&g1, big.NewInt(42))
	q1.ScalarMultiplication(&g2, b)
	ml := func(p bn254.G1Affine, q bn254.G2Affine) bn254.GT {
		res, err := bn254.MillerLoopFixedQ([]bn254.G1Affine{p},
			[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(q)})
		if err != nil {
			panic(err)
		}
		return res
	}
	offTwist := g2
	offTwist.X.A0.Add(&offTwist.X.A0, new(bnfp.Element).SetOne())
	pair, err := bn254.Pair([]bn254.G1Affine{p1}, []bn254.G2Affine{q1})
	if err != nil {
		t.Fatal(err)
	}
	return fixture[emparams.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl]{
		p1: sw_bn254.NewG1Affine(p1), p2: sw_bn254.NewG1Affine(p2), bad: sw_bn254.NewG1Affine(bad),
		q1: sw_bn254.NewG2Affine(q1), q2: sw_bn254.NewG2Affine(g2),
		nativeQ2:   g2,
		offTwistQ2: offTwist,
		prev:       sw_bn254.NewGTEl(ml(p2, g2)),
		nativePrev: ml(p2, g2),
		badPrev:    sw_bn254.NewGTEl(ml(bad, g2)),
		zero:       sw_bn254.NewGTEl(bn254.GT{}),
		millerLoop: sw_bn254.NewGTEl(ml(p1, q1)),
		pair:       sw_bn254.NewGTEl(pair),
	}
}

func bls12381Fixture(t testing.TB) fixture[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl] {
	_, _, g1, g2 := bls12381.Generators()
	a, b, negAB := randomScalars(t, blsfr.Modulus())
	var p1, p2, bad bls12381.G1Affine
	var q1 bls12381.G2Affine
	p1.ScalarMultiplication(&g1, a)
	p2.ScalarMultiplication(&g1, negAB)
	bad.ScalarMultiplication(&g1, big.NewInt(42))
	q1.ScalarMultiplication(&g2, b)
	ml := func(p bls12381.G1Affine, q bls12381.G2Affine) bls12381.GT {
		res, err := bls12381.MillerLoopFixedQ([]bls12381.G1Affine{p},
			[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{bls12381.PrecomputeLines(q)})
		if err != nil {
			panic(err)
		}
		return res
	}
	// gnark's BLS12-381 previous value is the conjugated Miller loop
	prevOf := func(p bls12381.G1Affine) bls12381.GT {
		res := ml(p, g2)
		return *res.Conjugate(&res)
	}
	offTwist := g2
	offTwist.X.A0.Add(&offTwist.X.A0, new(blsfp.Element).SetOne())
	pair, err := bls12381.Pair([]bls12381.G1Affine{p1}, []bls12381.G2Affine{q1})
	if err != nil {
		t.Fatal(err)
	}
	return fixture[emparams.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		p1: sw_bls12381.NewG1Affine(p1), p2: sw_bls12381.NewG1Affine(p2), bad: sw_bls12381.NewG1Affine(bad),
		q1: sw_bls12381.NewG2Affine(q1), q2: sw_bls12381.NewG2Affine(g2),
		nativeQ2:   g2,
		offTwistQ2: offTwist,
		prev:       sw_bls12381.NewGTEl(prevOf(p2)),
		nativePrev: prevOf(p2),
		badPrev:    sw_bls12381.NewGTEl(prevOf(bad)),
		zero:       sw_bls12381.NewGTEl(bls12381.GT{}),
		millerLoop: sw_bls12381.NewGTEl(ml(p1, q1)),
		pair:       sw_bls12381.NewGTEl(pair),
	}
}

// pairingCheckCircuit checks e(P1,Q1)·e(P2,Q2) == 1, with Q2 baked in as a
// constant carrying precomputed lines when fixedQ2 (a native point) is set.
// fixedQ2 is a Go-level field, not a witness variable -- the shape
// std/recursion gives its verifying key -- so the unassigned circuit has to
// carry it.
type pairingCheckCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	P1, P2 ringpairing.G1Affine[F]
	Q1, Q2 G2El

	fixedQ2 any
}

func (c *pairingCheckCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	pr.AssertIsOnG1(&c.P2)
	q2 := &c.Q2
	if c.fixedQ2 != nil {
		fixed := fixedG2[G2El](c.fixedQ2)
		q2 = &fixed
	}
	return pr.PairingCheck([]*ringpairing.G1Affine[F]{&c.P1, &c.P2}, []*G2El{&c.Q1, q2}, nil)
}

// previousCircuit checks e(P1,Q1)·previous == 1, like gnark's
// MultiMillerLoopAndFinalExpCircuit: the value never reaches the loop. With
// prevConst set, previous is built inside Define -- the verifier's shape --
// and travels as a constant rather than a witness.
type previousCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	P1   ringpairing.G1Affine[F]
	Q1   G2El
	Prev GtEl

	prevConst any
}

func (c *previousCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api)
	if err != nil {
		return err
	}
	pr.AssertIsOnG1(&c.P1)
	prev := &c.Prev
	if c.prevConst != nil {
		v := gtEl[GtEl](c.prevConst)
		prev = &v
	}
	return pr.PairingCheck([]*ringpairing.G1Affine[F]{&c.P1}, []*G2El{&c.Q1}, prev)
}

// previousOnlyCircuit has nothing left for the Miller loop to run over.
type previousOnlyCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	Prev GtEl
}

func (c *previousOnlyCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api)
	if err != nil {
		return err
	}
	return pr.PairingCheck(nil, nil, &c.Prev)
}

// pairCircuit asserts R is the reduced pairing e(P,Q), or with raw set the
// Miller loop value.
type pairCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	P ringpairing.G1Affine[F]
	Q G2El
	R GtEl

	raw bool
}

func (c *pairCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	pr, err := newPairing[F, G2El, GtEl](api)
	if err != nil {
		return err
	}
	f := pr.Pair
	if c.raw {
		f = pr.MillerLoop
	}
	res, err := f([]*ringpairing.G1Affine[F]{&c.P}, []*G2El{&c.Q})
	if err != nil {
		return err
	}
	pr.AssertIsEqual(res, &c.R)
	return nil
}

func TestPairing(t *testing.T) {
	t.Run("bn254", func(t *testing.T) { testPairing(t, bn254Fixture(t)) })
	t.Run("bls12-381", func(t *testing.T) { testPairing(t, bls12381Fixture(t)) })
}

func testPairing[F emulated.FieldParams, G2El, GtEl any](t *testing.T, fx fixture[F, G2El, GtEl]) {
	field := ecc.BN254.ScalarField()
	type check = pairingCheckCircuit[F, G2El, GtEl]
	type previous = previousCircuit[F, G2El, GtEl]
	type pair = pairCircuit[F, G2El, GtEl]

	t.Run("check", func(t *testing.T) {
		assignment := &check{P1: fx.p1, P2: fx.p2, Q1: fx.q1, Q2: fx.q2}
		test.NewAssert(t).NoError(test.IsSolved(&check{}, assignment, field))
	})

	// makes sure the check is not vacuous
	t.Run("check rejects non-pairing", func(t *testing.T) {
		assignment := &check{P1: fx.p1, P2: fx.bad, Q1: fx.q1, Q2: fx.q2}
		test.NewAssert(t).Error(test.IsSolved(&check{}, assignment, field))
	})

	// only Q1 runs the ladder in-circuit, Q2's lines are precomputed
	t.Run("fixed Q", func(t *testing.T) {
		assignment := &check{P1: fx.p1, P2: fx.p2, Q1: fx.q1, Q2: fx.q2}
		test.NewAssert(t).NoError(test.IsSolved(&check{fixedQ2: fx.nativeQ2}, assignment, field))
	})

	// makes sure precomputing the lines did not make the check vacuous
	t.Run("fixed Q rejects non-pairing", func(t *testing.T) {
		assignment := &check{P1: fx.p1, P2: fx.bad, Q1: fx.q1, Q2: fx.q2}
		test.NewAssert(t).Error(test.IsSolved(&check{fixedQ2: fx.nativeQ2}, assignment, field))
	})

	// pins gnark's behavior: baking a G2 point in skips the in-circuit
	// subgroup check, so NewG2AffineFixed panics off-circuit on a point
	// outside the subgroup (surfaced as an error by test.IsSolved).
	t.Run("fixed Q panics on bad point", func(t *testing.T) {
		assert := test.NewAssert(t)
		assignment := &check{P1: fx.p1, P2: fx.p2, Q1: fx.q1, Q2: fx.q2}
		err := test.IsSolved(&check{fixedQ2: fx.offTwistQ2}, assignment, field)
		assert.Error(err)
		assert.Contains(err.Error(), "not in the G2 subgroup")
	})

	t.Run("previous", func(t *testing.T) {
		assignment := &previous{P1: fx.p1, Q1: fx.q1, Prev: fx.prev}
		test.NewAssert(t).NoError(test.IsSolved(&previous{}, assignment, field))
	})

	// makes sure the folded-in value is not merely dropped
	t.Run("previous rejects non-pairing", func(t *testing.T) {
		assignment := &previous{P1: fx.p1, Q1: fx.q1, Prev: fx.badPrev}
		test.NewAssert(t).Error(test.IsSolved(&previous{}, assignment, field))
	})

	// refused rather than silently zeroing the product: the hint rejects it
	t.Run("previous rejects zero", func(t *testing.T) {
		assignment := &previous{P1: fx.p1, Q1: fx.q1, Prev: fx.zero}
		test.NewAssert(t).Error(test.IsSolved(&previous{}, assignment, field))
	})

	t.Run("previous constant", func(t *testing.T) {
		assignment := &previous{P1: fx.p1, Q1: fx.q1, Prev: fx.prev}
		test.NewAssert(t).NoError(test.IsSolved(&previous{prevConst: fx.nativePrev}, assignment, field))
	})

	// a product of nothing but a previous value constrains no witness, so a
	// circuit asking for one is a mistake
	t.Run("rejects previous only", func(t *testing.T) {
		assignment := &previousOnlyCircuit[F, G2El, GtEl]{Prev: fx.prev}
		test.NewAssert(t).Error(test.IsSolved(&previousOnlyCircuit[F, G2El, GtEl]{}, assignment, field))
	})

	// pins the ring Miller loop against gnark-crypto's pairing
	t.Run("pair", func(t *testing.T) {
		assignment := &pair{P: fx.p1, Q: fx.q1, R: fx.pair}
		test.NewAssert(t).NoError(test.IsSolved(&pair{}, assignment, field))
	})

	// Pins the raw Miller loop value -- not just the reduced pairing -- against
	// gnark-crypto's MillerLoopFixedQ. Which of gnark-crypto's two Miller loops
	// it matches is not incidental: MillerLoop runs the ladder in projective
	// coordinates and its raw value carries the lines' Z factors; they die in
	// the final exponentiation, but the pairing check never runs one. The
	// affine line form MillerLoopFixedQ evaluates is the one the loop here
	// uses and the one gnark's residue witness hints draw from.
	t.Run("miller loop matches fixed Q", func(t *testing.T) {
		assignment := &pair{P: fx.p1, Q: fx.q1, R: fx.millerLoop}
		test.NewAssert(t).NoError(test.IsSolved(&pair{raw: true}, assignment, field))
	})
}

// gnarkCheckCircuit is pairingCheckCircuit with gnark's pairing: the same
// statement, so the gap between the two counts is what the ring Miller loop
// saves over gnark's.
type gnarkCheckCircuit[F emulated.FieldParams, G2El, GtEl any] struct {
	P1, P2 ringpairing.G1Affine[F]
	Q1, Q2 G2El
}

func (c *gnarkCheckCircuit[F, G2El, GtEl]) Define(api frontend.API) error {
	var (
		pr  any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		pr, err = sw_bn254.NewPairing(api)
	case *sw_bls12381.G2Affine:
		pr, err = sw_bls12381.NewPairing(api)
	}
	if err != nil {
		return err
	}
	p := pr.(interface {
		AssertIsOnG1(*ringpairing.G1Affine[F])
		PairingCheck([]*ringpairing.G1Affine[F], []*G2El) error
	})
	p.AssertIsOnG1(&c.P1)
	p.AssertIsOnG1(&c.P2)
	return p.PairingCheck([]*ringpairing.G1Affine[F]{&c.P1, &c.P2}, []*G2El{&c.Q1, &c.Q2})
}

// BenchmarkPairingCheck compiles the two-pair check, both G2 points from the
// witness, with gnark's pairing and the ring pairing on both curves, and
// reports the constraint counts.
func BenchmarkPairingCheck(b *testing.B) {
	b.Run("bn254", func(b *testing.B) { benchPairingCheck(b, bn254Fixture(b)) })
	b.Run("bls12-381", func(b *testing.B) { benchPairingCheck(b, bls12381Fixture(b)) })
}

func benchPairingCheck[F emulated.FieldParams, G2El, GtEl any](b *testing.B, fx fixture[F, G2El, GtEl]) {
	bench.Circuit(b, func() frontend.Circuit { return &gnarkCheckCircuit[F, G2El, GtEl]{} },
		&gnarkCheckCircuit[F, G2El, GtEl]{P1: fx.p1, P2: fx.p2, Q1: fx.q1, Q2: fx.q2}, "gnark")
	bench.Circuit(b, func() frontend.Circuit { return &pairingCheckCircuit[F, G2El, GtEl]{} },
		&pairingCheckCircuit[F, G2El, GtEl]{P1: fx.p1, P2: fx.p2, Q1: fx.q1, Q2: fx.q2}, "ring")
}

// fixedG2 returns a native G2 point as a constant carrying precomputed lines.
func fixedG2[G2El any](q any) G2El {
	var res any
	switch q := q.(type) {
	case bn254.G2Affine:
		res = sw_bn254.NewG2AffineFixed(q)
	case bls12381.G2Affine:
		res = sw_bls12381.NewG2AffineFixed(q)
	}
	return res.(G2El)
}

// gtEl returns a native 𝔽p¹² element as a circuit value.
func gtEl[GtEl any](v any) GtEl {
	var res any
	switch v := v.(type) {
	case bn254.GT:
		res = sw_bn254.NewGTEl(v)
	case bls12381.GT:
		res = sw_bls12381.NewGTEl(v)
	}
	return res.(GtEl)
}

// newPairing returns the ring pairing from the curve package G2El belongs to.
func newPairing[F emulated.FieldParams, G2El, GtEl any](api frontend.API) (*ringpairing.Pairing[F, G2El, GtEl], error) {
	var (
		p   any
		err error
	)
	switch any((*G2El)(nil)).(type) {
	case *sw_bn254.G2Affine:
		p, err = ring_bn254.NewPairing(api)
	case *sw_bls12381.G2Affine:
		p, err = ring_bls12381.NewPairing(api)
	}
	if err != nil {
		return nil, err
	}
	return p.(*ringpairing.Pairing[F, G2El, GtEl]), nil
}
