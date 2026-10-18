package ringpairing

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns the hints this package defines. They are registered with
// the solver in this package's init; the residue witness and 𝔽p¹² inverse
// hints are gnark's own, see hints.go.
func GetHints() []solver.Hint {
	return []solver.Hint{divE2Hint}
}

// e2 is an 𝔽p² element a0 + a1·u with u² = -1: the quadratic extension both
// BN254 and BLS12-381 build their twists over. gnark has one such type per
// curve; the ladder below is written once against this one, and each curve
// converts at its G2Affine boundary.
type e2[F emulated.FieldParams] struct {
	A0, A1 emulated.Element[F]
}

// ext2 is gnark's fields_*.Ext2 arithmetic, generic in the base field. Every
// operation emits the same constraints as gnark's.
type ext2[F emulated.FieldParams] struct {
	api frontend.API
	fp  *emulated.Field[F]
}

func (e ext2[F]) zero() *e2[F] { return &e2[F]{A0: *e.fp.Zero(), A1: *e.fp.Zero()} }
func (e ext2[F]) one() *e2[F]  { return &e2[F]{A0: *e.fp.One(), A1: *e.fp.Zero()} }

// newConst returns the constant a0 + a1·u, given in decimal.
func (e ext2[F]) newConst(a0, a1 string) *e2[F] {
	return &e2[F]{A0: *e.fp.NewElement(a0), A1: *e.fp.NewElement(a1)}
}

func (e ext2[F]) add(x, y *e2[F]) *e2[F] {
	return &e2[F]{A0: *e.fp.Add(&x.A0, &y.A0), A1: *e.fp.Add(&x.A1, &y.A1)}
}

func (e ext2[F]) sub(x, y *e2[F]) *e2[F] {
	return &e2[F]{A0: *e.fp.Sub(&x.A0, &y.A0), A1: *e.fp.Sub(&x.A1, &y.A1)}
}

func (e ext2[F]) neg(x *e2[F]) *e2[F] {
	return &e2[F]{A0: *e.fp.Neg(&x.A0), A1: *e.fp.Neg(&x.A1)}
}

func (e ext2[F]) conjugate(x *e2[F]) *e2[F] {
	return &e2[F]{A0: x.A0, A1: *e.fp.Neg(&x.A1)}
}

func (e ext2[F]) mul(x, y *e2[F]) *e2[F] {
	type el = emulated.Element[F]
	return &e2[F]{
		A0: *e.fp.Eval([][]*el{{&x.A0, &y.A0}, {&x.A1, &y.A1}}, []int{1, -1}),
		A1: *e.fp.Eval([][]*el{{&x.A0, &y.A1}, {&x.A1, &y.A0}}, []int{1, 1}),
	}
}

func (e ext2[F]) square(x *e2[F]) *e2[F] {
	type el = emulated.Element[F]
	return &e2[F]{
		A0: *e.fp.Eval([][]*el{{&x.A0, &x.A0}, {&x.A1, &x.A1}}, []int{1, -1}),
		A1: *e.fp.Eval([][]*el{{&x.A0, &x.A1}}, []int{2}),
	}
}

func (e ext2[F]) mulByElement(x *e2[F], y *emulated.Element[F]) *e2[F] {
	return &e2[F]{A0: *e.fp.Mul(&x.A0, y), A1: *e.fp.Mul(&x.A1, y)}
}

func (e ext2[F]) mulByConst(x *e2[F], c int64) *e2[F] {
	k := big.NewInt(c)
	return &e2[F]{A0: *e.fp.MulConst(&x.A0, k), A1: *e.fp.MulConst(&x.A1, k)}
}

func (e ext2[F]) isZero(x *e2[F]) frontend.Variable {
	return e.api.And(e.fp.IsZero(&x.A0), e.fp.IsZero(&x.A1))
}

func (e ext2[F]) sel(selector frontend.Variable, z1, z0 *e2[F]) *e2[F] {
	return &e2[F]{A0: *e.fp.Select(selector, &z1.A0, &z0.A0), A1: *e.fp.Select(selector, &z1.A1, &z0.A1)}
}

func (e ext2[F]) assertIsEqual(x, y *e2[F]) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}

// divUnchecked returns x/y, hinted and constrained by x == (x/y)·y. For y == 0
// the quotient is unconstrained; see divWithZeroGuard.
func (e ext2[F]) divUnchecked(x, y *e2[F]) *e2[F] {
	res, err := e.fp.NewHint(divE2Hint, 2, &x.A0, &x.A1, &y.A0, &y.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	div := &e2[F]{A0: *res[0], A1: *res[1]}
	e.assertIsEqual(x, e.mul(div, y))
	return div
}

// divWithZeroGuard computes n/d as a line slope, but for d == 0 it returns 0
// with the quotient constrained to 0 rather than left as a free hint value. A
// plain divUnchecked(n, 0) only enforces λ·0 == n, i.e. 0 == 0, which leaves λ
// unconstrained -- the soundness gap when the point at infinity (0,0) reaches
// the Miller loop and every affine line evaluation becomes 0/0.
func (e ext2[F]) divWithZeroGuard(n, d *e2[F]) *e2[F] {
	dIsZero := e.isZero(d)
	dSafe := e.sel(dIsZero, e.one(), d)
	return e.sel(dIsZero, e.zero(), e.divUnchecked(n, dSafe))
}

// divE2Hint computes x/y in 𝔽p[u]/(u²+1) for whichever p the emulated field
// carries: (x0 + x1·u)/(y0 + y1·u) = x·(y0 - y1·u)/(y0² + y1²).
func divE2Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			x0, x1, y0, y1 := inputs[0], inputs[1], inputs[2], inputs[3]
			norm := new(big.Int).Mul(y0, y0)
			norm.Add(norm, new(big.Int).Mul(y1, y1)).Mod(norm, mod)
			if norm.ModInverse(norm, mod) == nil {
				// y == 0: the zero guard discards this quotient
				outputs[0].SetUint64(0)
				outputs[1].SetUint64(0)
				return nil
			}
			// (x0 + x1·u)(y0 - y1·u) = (x0y0 + x1y1) + (x1y0 - x0y1)·u
			a := new(big.Int).Mul(x0, y0)
			a.Add(a, new(big.Int).Mul(x1, y1)).Mul(a, norm).Mod(a, mod)
			b := new(big.Int).Mul(x1, y0)
			b.Sub(b, new(big.Int).Mul(x0, y1)).Mul(b, norm).Mod(b, mod)
			outputs[0].Set(a)
			outputs[1].Set(b)
			return nil
		})
}
