package polyring

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// PolyRingChecker tracks the polynomial ring checks a circuit has queued, and
// verifies them all once Define returns. One checker can hold several rings,
// registered with [PolyRingChecker.NewPolyRingCheck]; each is batched
// independently against its own modulus, but they share the two Fiat-Shamir
// challenges and so cost only one pair of commitments between them.
type PolyRingChecker[T emulated.FieldParams] struct {
	fp     T
	checks []*PolyRingGroupChecks[T]
	f      *emulated.Field[T]
	api    frontend.API
}

// NewPolyRingChecker creates a new PolyRingChecker instance. It registers the
// deferred polynomial ring checks with the compiler so that verification runs
// after circuit.Define() completes.
//
// Call it before anything else in the circuit creates an emulated field: the
// ring checks emit range checks of their own, and gnark runs deferred callbacks
// in registration order, so the range checker -- created with the first
// emulated field -- has to be registered after this one or it will already be
// closed by the time the ring checks run.
func NewPolyRingChecker[T emulated.FieldParams](api frontend.API) *PolyRingChecker[T] {
	var fp T
	prc := &PolyRingChecker[T]{
		fp:  fp,
		api: api,
	}
	api.Compiler().Defer(prc.performDeferredRingChecks)

	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}

	prc.f = f

	return prc
}

// Field returns the emulated field the checker operates over. Callers building
// ring elements on top of [PolyRingChecker] need it for the coefficient-wise
// operations (Add, Sub, Eval, ...) that don't go through the ring.
func (prc *PolyRingChecker[T]) Field() *emulated.Field[T] {
	return prc.f
}

// PolyRingGroupChecks is one ring: a modulus, and every product claimed
// against it. Claims in a group are batched together into the single identity
// asserted at the Schwartz-Zippel challenge point.
//
// The identity each claim contributes is
//
//	∏ᵢ inputsᵢ = r + q·mod
//
// where
//
//   - inputs are the operands, each a [Poly] of reduced coefficients;
//   - mod is the polynomial defining the ring, treated as a constant;
//   - r is the product reduced modulo mod, i.e. the remainder, which is what
//     [PolyRingChecker.MulPolyRings] returns to the caller;
//   - q is the quotient of the product divided by mod.
//
// Both sides are evaluated at a single random challenge α drawn from a
// commitment to all the coefficients. If a polynomial f has coefficient
// elements (f_0, ..., f_n), its evaluation is
//
//	f(α) = ∑ᵢ f_i(α)·αⁱ,
//
// where each f_i(α) is itself the Schwartz-Zippel evaluation of the limb
// polynomial of the emulated element f_i. A single claim then reads
//
//	∏ᵢ inputsᵢ(α) = r(α) + q(α)·mod(α).
//
// What is actually asserted is the random linear combination of every claim in
// the group,
//
//	∑ᵢ zⁱ·(∏ⱼ inputsᵢⱼ(x) − rᵢ(x)) == (∑ᵢ zⁱ·qᵢ)(x)·mod(x),
//
// which lets the quotient fold ∑ᵢ zⁱ·qᵢ be computed outside the circuit and
// evaluated once, instead of evaluating every qᵢ in-circuit.
type PolyRingGroupChecks[T emulated.FieldParams] struct {
	mod       *Poly[T]              // polynomial defining the ring
	modEvalFn EvalFnType[T]         // evaluation of mod at the challenge point, set at check time
	checks    []polyRingMulCheck[T] // individual operations to check
	qAcc      *Poly[T]              // random linear combination of quotients ∑_i z^i * q_i
	toCommit  []frontend.Variable   // additional variable which should be committed to.
}

// polyRingMulCheck is an individual deferred check.
type polyRingMulCheck[T emulated.FieldParams] struct {
	// ∏_i inputs_i = r + q * mod
	inputs []*Poly[T] // input polynomials
	r      *Poly[T]   // remainder
	q      *Poly[T]   // quotient
}

// NewPolyRingCheck registers a new polynomial ring group with the given modulus
// and returns it. Pass nil for modEvalFn for default polynomial evaluation; a
// sparse modulus is usually cheaper to evaluate as a closure than through the
// generic inner product.
func (prc *PolyRingChecker[T]) NewPolyRingCheck(mod *Poly[T], modEvalFn EvalFnType[T]) *PolyRingGroupChecks[T] {
	groupCheck := &PolyRingGroupChecks[T]{
		mod:       mod,
		modEvalFn: modEvalFn,
	}
	prc.checks = append(prc.checks, groupCheck)

	return groupCheck
}

// ToCommit adds additional variables to commit to for obtaining the
// Schwartz-Zippel challenge. Every operand of a claimed product that the prover
// chooses has to be fixed before the challenge is drawn, so circuit inputs and
// hinted values alike go through here.
//
// It matters most for hinted values whose correctness is asserted by a ring
// operation itself: for a hinted inverse x_inv checked as x * x_inv = 1 + q *
// mod, the hinted x_inv is an operand of that very check and so has to be
// committed to.
func (group *PolyRingGroupChecks[T]) ToCommit(elements ...*emulated.Element[T]) {
	for _, e := range elements {
		if e != nil {
			group.toCommit = append(group.toCommit, e.Limbs...)
		}
	}
}
