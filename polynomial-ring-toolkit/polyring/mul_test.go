package polyring

import (
	"math/big"
	"testing"
)

func bigs(vs ...int64) []*big.Int {
	out := make([]*big.Int, len(vs))
	for i, v := range vs {
		out[i] = big.NewInt(v)
	}
	return out
}

// TestPolyRingMul checks the off-circuit Euclidean division the prover's hint
// relies on: the product of the inputs must equal r + q·mod exactly.
func TestPolyRingMul(t *testing.T) {
	p := big.NewInt(97)

	for _, tc := range []struct {
		name   string
		inputs [][]*big.Int
		mod    []*big.Int
		wantQ  []*big.Int
		wantR  []*big.Int
	}{
		{
			// (1+2x)(3+4x) = 3 + 10x + 8x² = 8·(x²−2) + (19 + 10x)
			name:   "quadratic",
			inputs: [][]*big.Int{bigs(1, 2), bigs(3, 4)},
			mod:    bigs(-2, 0, 1),
			wantQ:  bigs(8),
			wantR:  bigs(19, 10),
		},
		{
			// degree below the modulus: quotient is zero, remainder is the product
			name:   "below modulus degree",
			inputs: [][]*big.Int{bigs(1, 2), bigs(3, 0)},
			mod:    bigs(-2, 0, 0, 1),
			wantQ:  bigs(0),
			wantR:  bigs(3, 6, 0),
		},
		{
			// three factors at once, all folded into one division
			name:   "three factors",
			inputs: [][]*big.Int{bigs(1, 1), bigs(1, 1), bigs(1, 1)},
			mod:    bigs(-2, 0, 1),
			wantQ:  bigs(3, 1),
			wantR:  bigs(7, 5),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, r, err := polyRingMul(p, tc.inputs, tc.mod)
			if err != nil {
				t.Fatalf("polyRingMul: %v", err)
			}
			assertPolyEqual(t, "quotient", q, tc.wantQ, p)
			assertPolyEqual(t, "remainder", r, tc.wantR, p)

			// and the identity itself: ∏ inputs == r + q·mod
			lhs := mulPolys(p, tc.inputs)
			rhs := addPolys(p, r, mulPoly(p, q, tc.mod))
			assertPolyEqual(t, "∏ inputs == r + q·mod", lhs, rhs, p)
		})
	}
}

func TestPolyRingMulErrors(t *testing.T) {
	p := big.NewInt(97)
	if _, _, err := polyRingMul(p, nil, bigs(-2, 0, 1)); err == nil {
		t.Error("no input polynomials: want error, got nil")
	}
	if _, _, err := polyRingMul(p, [][]*big.Int{bigs(1)}, nil); err == nil {
		t.Error("empty modulus: want error, got nil")
	}
	// leading coefficient 0 is not invertible modulo p
	if _, _, err := polyRingMul(p, [][]*big.Int{bigs(1, 2, 3)}, bigs(1, 0)); err == nil {
		t.Error("singular leading coefficient: want error, got nil")
	}
}

func assertPolyEqual(t *testing.T, what string, got, want []*big.Int, p *big.Int) {
	t.Helper()
	n := max(len(got), len(want))
	for i := range n {
		g, w := new(big.Int), new(big.Int)
		if i < len(got) {
			g.Mod(got[i], p)
		}
		if i < len(want) {
			w.Mod(want[i], p)
		}
		if g.Cmp(w) != 0 {
			t.Errorf("%s: coefficient %d = %s, want %s", what, i, g, w)
		}
	}
}

// mulPoly multiplies two polynomials over 𝔽p, schoolbook.
func mulPoly(p *big.Int, a, b []*big.Int) []*big.Int {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]*big.Int, len(a)+len(b)-1)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i, ai := range a {
		for j, bj := range b {
			out[i+j].Add(out[i+j], new(big.Int).Mul(ai, bj))
			out[i+j].Mod(out[i+j], p)
		}
	}
	return out
}

func mulPolys(p *big.Int, polys [][]*big.Int) []*big.Int {
	out := polys[0]
	for _, poly := range polys[1:] {
		out = mulPoly(p, out, poly)
	}
	return out
}

func addPolys(p *big.Int, a, b []*big.Int) []*big.Int {
	out := make([]*big.Int, max(len(a), len(b)))
	for i := range out {
		out[i] = new(big.Int)
		if i < len(a) {
			out[i].Add(out[i], a[i])
		}
		if i < len(b) {
			out[i].Add(out[i], b[i])
		}
		out[i].Mod(out[i], p)
	}
	return out
}
