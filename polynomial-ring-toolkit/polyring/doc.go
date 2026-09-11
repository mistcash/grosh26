// Package polyring is a deferred product checker for polynomial rings
// 𝔽p[x]/(mod) built inside [gnark] circuits, where 𝔽p is a field emulated in
// the circuit's native field.
//
// # The problem
//
// Emulating a large field inside a smaller one is expensive because every
// product has to be reduced against the field modulus as soon as it is
// computed. A circuit that does arithmetic in an extension 𝔽p^n pays that
// cost n² times per extension-field product.
//
// # The approach
//
// This package takes the other route: a product is *claimed* rather than
// computed. The prover supplies the quotient and remainder of
//
//	∏ᵢ inputsᵢ = r + q·mod
//
// through a hint, the caller gets r back immediately, and the claim is queued.
// Every claim made anywhere in the circuit is then verified together, as one
// batched polynomial identity checked at a random point once Define returns.
// The batching uses two rounds of Fiat-Shamir over the circuit's commitment
// scheme, following the Extension Field Arithmetic IOP of
// [On Proving Pairings], Section 5.2:
//
//  1. commit to every remainder, giving challenge z;
//  2. fold the quotients off-circuit into qAcc = Σᵢ zⁱ·qᵢ — this is the
//     saving: without folding, every quotient needs its own in-circuit
//     evaluation;
//  3. commit to qAcc, giving challenge x;
//  4. assert Σᵢ zⁱ·(∏ⱼ inputsᵢⱼ(x) − rᵢ(x)) == qAcc(x)·mod(x).
//
// # Scope
//
// Nothing here is specific to any particular ring, curve or proof system. The
// modulus is whatever polynomial you register with [PolyRingChecker.NewPolyRingCheck],
// the coefficient field is any [emulated.FieldParams], and a single checker can
// hold several rings at once, each batched independently against its own
// modulus. Extension-field arithmetic for pairings is one instantiation; so is
// any other structure whose multiplication is polynomial multiplication modulo
// a fixed polynomial.
//
// # Using it
//
// Create one checker per circuit, before anything else in the circuit creates
// an emulated field:
//
//	prc := polyring.NewPolyRingChecker[emulated.BN254Fp](api)
//	ring := prc.NewPolyRingCheck(prc.MakePoly(82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0, 1), nil)
//
//	x, y := prc.MakePoly(...), prc.MakePoly(...)
//	ring.ToCommit(x.Coeffs...)
//	ring.ToCommit(y.Coeffs...)
//	xy, err := prc.MulPolyRings(ring, x, y)
//
// Ordering matters in two places, and both are soundness-critical:
//
//   - [NewPolyRingChecker] registers the deferred check with the compiler, and
//     gnark runs deferred callbacks in registration order. The range checker is
//     registered when the first emulated field is created, and the ring checks
//     emit range checks of their own, so the checker has to come first or the
//     range checker will already be closed when the ring checks run.
//
//   - Every operand of a claimed product that the prover chooses — circuit
//     inputs and hinted values alike — has to be committed with
//     [PolyRingGroupChecks.ToCommit] before the challenge is drawn, or the
//     prover can pick it after seeing the challenge.
//
// # Status
//
// Unaudited. See the README for the soundness argument and the open questions
// an external review has not yet resolved.
//
// [gnark]: https://github.com/Consensys/gnark
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
package polyring
