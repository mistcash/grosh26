package polyring

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/internal/limbs"
)

// performDeferredRingChecks performs the deferred polynomial checks.
// prover provides results of ring multiplications - remainders and quotients
//  1. commit the remainders to obtain a random challenge z for random
//     linear combination of all quotients
//  2. batch the quotients with adjacent powers RLC using challenge z
//     qAcc = ∑_i z^i * q_i
//  3. commit the quotients rlc with challenge z to obtain challenge x
//  4. assert equality of remainders and quotients rlc polynomials at x
//     i.e. ∑_i z^i * ( ∏_j inputs_j(x) - r_i(x) ) == (∑_i z^i * q_i)(x) * mod_i(x)
//
// savings come from batching quotients outside the circuit – qAcc = ∑_i z^i * q_i
func (prc *PolyRingChecker[T]) performDeferredRingChecks(api frontend.API) error {
	// use given api. We are in defer and API may be different to what we have
	// stored.

	if len(prc.checks) == 0 {
		return nil
	}

	// get committer from the api
	committer, ok := api.(frontend.Committer)
	if !ok {
		panic("compiler doesn't implement frontend.Committer")
	}

	// 1. commit the remainders

	// prepare all remainder coefficients to commit to from each group
	var remainderCoeffCommits []frontend.Variable
	for _, group := range prc.checks {

		// additional variables to commit to for obtaining schwartz zippel lemma challenge.
		remainderCoeffCommits = append(remainderCoeffCommits, group.toCommit...)

		for _, check := range group.checks {
			for _, rCoeff := range check.r.Coeffs {
				remainderCoeffCommits = append(remainderCoeffCommits, rCoeff.Limbs...)
			}
		}
	}

	if len(remainderCoeffCommits) == 0 {
		// nothing to do
		return nil
	}

	// commit all remainders from each group at once
	z, err := committer.Commit(remainderCoeffCommits...) // z = remainderCommitment
	if err != nil {
		return fmt.Errorf("deferredPolyCheck commit error: %w", err)
	}

	// 2. batch and store quotients from each group and prepare to commit

	// z can be shared across all groups
	quotientbatchesCoeffCommits := []frontend.Variable{z}
	for _, group := range prc.checks {
		quotients := make([]*Poly[T], len(group.checks))
		for i, check := range group.checks {
			quotients[i] = check.q
		}

		// qAcc = ∑_i z^i * q_i
		group.qAcc, err = prc.callQuotientsRLCHint(quotients, z)

		if err != nil {
			return fmt.Errorf("deferredPolyCheck callQuotientsRLCHint error: %w", err)
		}

		// commit quotient rlc coefficients from each group
		for _, qCoeff := range group.qAcc.Coeffs {
			if qCoeff == nil {
				continue
			}
			quotientbatchesCoeffCommits = append(quotientbatchesCoeffCommits, qCoeff.Limbs...)
		}
	}

	// 3. commit the quotients
	x, err := committer.Commit(quotientbatchesCoeffCommits...)
	if err != nil {
		return fmt.Errorf("deferredPolyCheck quotient commit error: %w", err)
	}

	// Decompose challenges into emulated elements at full native width: per
	// the Fiat-Shamir construction from eprint 2024/640, the Schwartz-Zippel
	// challenge is the verifier-side commitment randomness itself, used in
	// full -- not a truncated prefix of it.
	nativesToEl, err := prc.NativeToEmulated(z, x)
	if err != nil {
		return fmt.Errorf("NativeToEmulated error: %w", err)
	}
	zEmulated := nativesToEl[0]
	xEmulated := nativesToEl[1]

	maxTerms := 1
	maxChecks := 1
	for _, group := range prc.checks {
		maxTerms = max(maxTerms, len(group.mod.Coeffs), len(group.qAcc.Coeffs))
		for _, check := range group.checks {
			for _, input := range check.inputs {
				maxTerms = max(maxTerms, len(input.Coeffs))
			}
		}
		maxChecks = max(maxChecks, len(group.checks))
	}

	xPowers := make([]*emulated.Element[T], maxTerms)
	xPowers[0] = prc.f.One()
	if maxTerms > 1 {
		xPowers[1] = xEmulated
		for i := 2; i < maxTerms; i++ {
			xPowers[i] = prc.f.Mul(xPowers[i-1], xEmulated)
		}
	}

	zPowers := make([]*emulated.Element[T], maxChecks)
	zPowers[0] = prc.f.One()
	if maxChecks > 1 {
		zPowers[1] = zEmulated
		for i := 2; i < maxChecks; i++ {
			zPowers[i] = prc.f.Mul(zPowers[i-1], zEmulated)
		}
	}

	// 4. assert the ring check at x for each group
	for _, group := range prc.checks {
		// lhsRlc = ∑_i z^i * (∏_j inputs_i_j(x) - r_i(x))
		lhsEvals := make([]*emulated.Element[T], len(group.checks))

		// Evaluations don't need to be reduced, we can reduce at the very end to
		// when asserting equality.
		for i, check := range group.checks {
			// lhs = inputs_0(x)
			lhs := prc.evalPolyWithChallenge(check.inputs[0], xPowers)

			// lhs = ∏_j inputs_j(x)
			for j := 1; j < len(check.inputs); j++ {
				lhs = prc.f.Mul(lhs, prc.evalPolyWithChallenge(check.inputs[j], xPowers))
			}

			// compute (∏_j inputs_j(x)) - r(x)
			lhs = prc.f.Sub(lhs, prc.evalPolyWithChallenge(check.r, xPowers))
			lhsEvals[i] = lhs
		}

		lhsRlc := prc.InnerProductNoReduce(lhsEvals, zPowers)
		lhsRlc = prc.f.Reduce(lhsRlc)

		if group.modEvalFn == nil {
			group.modEvalFn = func(xPowers []*emulated.Element[T]) *emulated.Element[T] {
				return prc.evalPolyWithChallenge(group.mod, xPowers)
			}
		}

		// compute qAcc(x) * mod(x)
		qAcc := prc.evalPolyWithChallenge(group.qAcc, xPowers)
		// qAcc = prc.f.Reduce(qAcc)

		// compute qAcc(x) * mod(x)
		rhs := prc.f.MulNoReduce(qAcc, group.modEvalFn(xPowers))

		// AssertIsEqual reduces inputs for comparison
		prc.f.AssertIsEqual(lhsRlc, rhs)
	}

	// cleanup all deffered polynomial ring checks
	prc.checks = nil

	return nil
}

// callQuotientsRLCHint computes the random linear combination ∑_i z^i * q_i of
// the provided quotient polynomials with the scalar challenge z. The result is
// a single Poly[T] whose coefficients are emulated field elements reduced
// modulo the emulated field prime. This is used in the deferred ring check to
// batch multiple quotient polynomials together outside the circuit, saving
// constraints by avoiding individual quotient evaluations.
func (prc *PolyRingChecker[T]) callQuotientsRLCHint(quotients []*Poly[T], z frontend.Variable) (*Poly[T], error) {
	if len(quotients) == 0 {
		return nil, fmt.Errorf("BatchPolyQuotients: no quotient polynomials")
	}

	nbLimbs, nbBits := int(prc.fp.NbLimbs()), prc.fp.BitsPerLimb()

	// the output polynomial has the maximum number of terms among all inputs
	maxTerms := 0
	for _, q := range quotients {
		if len(q.Coeffs) > maxTerms {
			maxTerms = len(q.Coeffs)
		}
	}

	nbPolys := len(quotients)

	// hint input layout: nbBits | nbLimbs | nbPolys | fieldMod | z | for each poly: nbTerms | limbs...
	hintInputs := make([]frontend.Variable, 0, 5+nbLimbs+nbPolys) // nbLimbs from modulus Element
	hintInputs = append(hintInputs, nbBits, nbLimbs, prc.fullChallengeLimbs(), nbPolys, z)
	hintInputs = append(hintInputs, prc.f.Modulus().Limbs...)

	for _, q := range quotients {
		hintInputs = prc.serialisePoly(q, hintInputs)
	}

	nbOutputs := maxTerms * nbLimbs
	ret, err := prc.api.NewHint(quotientsRLCHint, nbOutputs, hintInputs...)
	if err != nil {
		return nil, fmt.Errorf("BatchPolyQuotients hint: %w", err)
	}

	result := &Poly[T]{Coeffs: make([]*emulated.Element[T], maxTerms)}
	for i := range result.Coeffs {
		termLimbs := ret[i*nbLimbs : (i+1)*nbLimbs]
		result.Coeffs[i] = prc.f.UnsafeFromLimbs(termLimbs)
	}

	return result, nil
}

// quotientsRLCHint computes ∑_i z^i * q_i for a list of quotient
// polynomials and a scalar challenge z. Each output coefficient is
// result[j] = ∑_i z^i * q_i[j] mod fieldMod, where fieldMod is the emulated
// field prime. Should not be called directly; use [Field.BatchPolyQuotients].
func quotientsRLCHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 5 {
		return fmt.Errorf("batchPolyQuotientsHint: not enough inputs")
	}
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbChallengeLimbs := int(inputs[2].Int64())
	nbPolys := int(inputs[3].Int64())
	// nbChallengeLimbs is sized to the challenge's full native width (see
	// PolyRingChecker.fullChallengeLimbs), so this mask never truncates z.
	nbChallengeBits := uint(nbBits * nbChallengeLimbs)

	z := new(big.Int) // full z
	base := new(big.Int).Lsh(one, nbChallengeBits)
	base.Sub(base, one)    // 0b111...1111 challenge bits
	z.And(inputs[4], base) // mask z to its full native width

	nbMetaDataVars := 5 + int(nbLimbs)

	fieldMod := new(big.Int)
	limbs.Recompose(inputs[5:nbMetaDataVars], uint(nbBits), fieldMod)

	ptr := nbMetaDataVars // skip metadata and modulus limbs
	polys := make([][]*big.Int, nbPolys)
	for i := 0; i < nbPolys; i++ {
		nbTerms := int(inputs[ptr].Int64())
		ptr++
		polys[i] = make([]*big.Int, nbTerms)
		for j := 0; j < nbTerms; j++ {
			coeffLimbs := inputs[ptr : ptr+nbLimbs]
			ptr += nbLimbs
			val := new(big.Int)
			if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
				return fmt.Errorf("recompose polys[%d][%d]: %w", i, j, err)
			}
			polys[i][j] = val
		}
	}
	maxTerms := len(outputs) / nbLimbs
	// accumulator: result[j] = ∑_i z^i * q_i[j] mod fieldMod
	result := make([]*big.Int, maxTerms)
	for i := range result {
		result[i] = new(big.Int)
	}
	zPow := new(big.Int).SetInt64(1) // z^0 = 1
	tmp := new(big.Int)
	for _, poly := range polys {
		for j, coeff := range poly {
			tmp.Mul(zPow, coeff)
			tmp.Mod(tmp, fieldMod)
			result[j].Add(result[j], tmp)
			result[j].Mod(result[j], fieldMod)
		}
		zPow.Mul(zPow, z)
		zPow.Mod(zPow, fieldMod)
	}
	// serialize: maxTerms coefficients each decomposed into nbLimbs limbs
	outptr := 0
	for idx, coeff := range result {
		if err := limbs.Decompose(coeff, uint(nbBits), outputs[outptr:outptr+nbLimbs]); err != nil {
			return fmt.Errorf("decompose result[%d]: %w", idx, err)
		}
		outptr += nbLimbs
	}
	return nil
}
