package polyring

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/internal/limbs"
)

// MulPolyRings computes a polynomial product check in a polynomial ring,
// returns the remainder (reduced result) and the quotient. The computation
// is performed inside a hint, so it is the callers responsibility to perform
// the deferred polynomial ring multiplication check.
func (prc *PolyRingChecker[T]) MulPolyRings(group *PolyRingGroupChecks[T], inputs_ ...*Poly[T]) (rem *Poly[T], err error) {
	// guards against replacing the entries in inputs_ slice but preserves
	// pointers to each *Poly[T] for cached evaluations
	inputs := make([]*Poly[T], len(inputs_))
	copy(inputs, inputs_)

	mod := *group.mod
	nbLimbs, nbBits := int(prc.fp.NbLimbs()), prc.fp.BitsPerLimb()

	// total number of terms for all input polynomials
	nbTerms := 0
	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		// add degree of each input polynomial
		nbTerms += len(inputPoly.Coeffs)
	}

	// metadata for hint inputs
	nbPoly := len(inputs)
	nbTermsLimbs := nbTerms * nbLimbs
	nbModTermsLimbs := len(mod.Coeffs) * nbLimbs

	// metadata for outputs
	modDegree := len(mod.Coeffs) - 1
	nbRemLimbs := modDegree * nbLimbs
	totalDegree := nbTerms - nbPoly
	// q degree is total degree minus the degree of the modulus polynomial
	qDegree := totalDegree - modDegree
	if qDegree < 0 {
		qDegree = 0
	}
	nbQTermsLimbs := (1 + qDegree) * nbLimbs

	nbMetaDataVars := 3 + int(nbBits)
	// polynomials serialised as nbTerms|...terms. hintInputs contains
	// serialisation of: nbBits|nbLimbs|nbPoly|fieldMod|...inputs|modPoly,
	// where inputs and mod are serialised as polynomials
	hintInputs := make([]frontend.Variable, 0, nbMetaDataVars+(nbPoly+nbTermsLimbs)+(1+nbModTermsLimbs))

	hintInputs = append(hintInputs, nbBits, nbLimbs, nbPoly)
	hintInputs = append(hintInputs, prc.f.Modulus().Limbs...)

	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		hintInputs = prc.serialisePoly(inputPoly, hintInputs)
	}

	hintInputs = prc.serialisePoly(&mod, hintInputs)

	// call
	ret, err := prc.api.NewHint(polyRingMulHint, 1+nbQTermsLimbs+1+nbRemLimbs, hintInputs...)

	if err != nil {
		return nil, err
	}

	// unpack quotient: skip nbQTerms header, then read (1+qDegree) terms of nbLimbs each
	quo := &Poly[T]{Coeffs: make([]*emulated.Element[T], 1+qDegree)}
	retPtr := 1 // skip nbQTerms
	for i := range quo.Coeffs {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		// quotient is only used by the prover to generate the rlc, so don't need
		// rangechecks on these
		quo.Coeffs[i] = prc.f.UnsafeFromLimbs(termLimbs)
	}

	// unpack remainder: skip nbRemTerms header, then read len(mod)-1 terms of nbLimbs each
	retPtr++ // skip nbRemTerms
	rem = &Poly[T]{Coeffs: make([]*emulated.Element[T], len(mod.Coeffs)-1)}
	for i := range rem.Coeffs {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		rem.Coeffs[i] = prc.f.NewElement(termLimbs)
	}

	group.checks = append(group.checks, polyRingMulCheck[T]{
		inputs: inputs,
		r:      rem,
		q:      quo,
	})

	return rem, nil
}

// polyRingMulHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.MulPolyRings] method which
// handles the input packing and output unpacking.
func polyRingMulHint(mod *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbPoly := int(inputs[2].Int64())
	fieldMod := new(big.Int)
	nbMetaDataVars := 3 + int(nbLimbs)
	limbs.Recompose(inputs[3:nbMetaDataVars], uint(nbBits), fieldMod)

	// extract the input polynomials
	inputsPolys := make([][]*big.Int, nbPoly)
	ptr := nbMetaDataVars // skip metadata and modulus limbs

	for i := 0; i < nbPoly; i++ {
		nbTerms := int(inputs[ptr].Int64())
		ptr++
		inputsPolys[i] = make([]*big.Int, nbTerms)
		for j := 0; j < nbTerms; j++ {
			coeffLimbs := inputs[ptr : ptr+nbLimbs]
			ptr += nbLimbs
			val := new(big.Int)
			if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
				return fmt.Errorf("recompose input[%d][%d]: %w", i, j, err)
			}
			inputsPolys[i][j] = val
		}
	}

	nbModPolyTerms := int(inputs[ptr].Int64())
	ptr++
	modPoly := make([]*big.Int, nbModPolyTerms)
	for j := 0; j < nbModPolyTerms; j++ {
		coeffLimbs := inputs[ptr : ptr+nbLimbs]
		ptr += nbLimbs
		val := new(big.Int)
		if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
			return fmt.Errorf("recompose mod polynomial[%d]: %w", j, err)
		}
		modPoly[j] = val
	}

	// multiply inputs and divide by modPoly to obtain quotient and remainder
	q, r, err := polyRingMul(fieldMod, inputsPolys, modPoly)
	if err != nil {
		return fmt.Errorf("polyRingMul: %w", err)
	}

	// serialize outputs: nbQTerms | q limbs... | nbRemTerms | r limbs...
	nbBitsU := uint(nbBits)
	outptr := 0
	outputs[outptr].SetInt64(int64(len(q)))
	outptr++
	for _, coeff := range q {
		if err := limbs.Decompose(coeff, nbBitsU, outputs[outptr:outptr+nbLimbs]); err != nil {
			return fmt.Errorf("decompose quotient coeff: %w", err)
		}
		outptr += nbLimbs
	}
	outputs[outptr].SetInt64(int64(len(r)))
	outptr++
	for _, coeff := range r {
		if err := limbs.Decompose(coeff, nbBitsU, outputs[outptr:outptr+nbLimbs]); err != nil {
			return fmt.Errorf("decompose remainder coeff: %w", err)
		}
		outptr += nbLimbs
	}

	return nil
}

// polyRingMul multiplies all polynomials in inputs and divides the product
// by modPoly using polynomial Euclidean division. Coefficients are reduced
// modulo fieldMod (the emulated field prime).
func polyRingMul(fieldMod *big.Int, inputs [][]*big.Int, modPoly []*big.Int) (quotient, remainder []*big.Int, err error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: no input polynomials")
	}
	if len(modPoly) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: modulus polynomial is empty")
	}

	// multiply all polynomials in inputs
	product := make([]*big.Int, len(inputs[0]))
	for i, c := range inputs[0] {
		product[i] = new(big.Int).Mod(c, fieldMod)
	}
	for k := 1; k < len(inputs); k++ {
		b := inputs[k]
		result := make([]*big.Int, len(product)+len(b)-1)
		for i := range result {
			result[i] = new(big.Int)
		}
		tmp := new(big.Int)
		for i, ci := range product {
			for j, cj := range b {
				tmp.Mul(ci, cj)
				result[i+j].Add(result[i+j], tmp)
				result[i+j].Mod(result[i+j], fieldMod)
			}
		}
		product = result
	}

	// euclidean division: product = quotient * modPoly + remainder
	divisorDeg := len(modPoly) - 1

	// if product has lower degree than modPoly, quotient is 0 and remainder is product
	if len(product)-1 < divisorDeg {
		remainder := make([]*big.Int, divisorDeg)
		for i := range remainder {
			if i < len(product) {
				remainder[i] = new(big.Int).Set(product[i])
			} else {
				remainder[i] = new(big.Int)
			}
		}
		return []*big.Int{new(big.Int)}, remainder, nil
	}

	// leading coefficient inverse of modPoly modulo field modulus
	lcInv := new(big.Int).ModInverse(modPoly[divisorDeg], fieldMod)
	if lcInv == nil {
		return nil, nil, fmt.Errorf("polyRingMul: leading coefficient of modulus polynomial is not invertible")
	}

	dividend := make([]*big.Int, len(product))
	for i, c := range product {
		dividend[i] = new(big.Int).Set(c)
	}

	qDeg := len(product) - 1 - divisorDeg
	quotient = make([]*big.Int, qDeg+1)
	for i := range quotient {
		quotient[i] = new(big.Int)
	}

	lc := new(big.Int)
	term := new(big.Int)
	for len(dividend) >= len(modPoly) {
		d := len(dividend) - len(modPoly)
		// leading quotient term at degree d
		lc = lc.Mul(dividend[len(dividend)-1], lcInv)
		lc.Mod(lc, fieldMod)
		quotient[d].Set(lc)
		// subtract lc * x^d * modPoly from dividend
		for i, c := range modPoly {
			term = term.Mul(lc, c)
			dividend[i+d].Sub(dividend[i+d], term)
			dividend[i+d].Mod(dividend[i+d], fieldMod)
		}
		// trim leading zeros
		for len(dividend) > 0 && dividend[len(dividend)-1].Sign() == 0 {
			dividend = dividend[:len(dividend)-1]
		}
	}

	// pad remainder to divisorDeg terms
	remainder = make([]*big.Int, divisorDeg)
	for i := range remainder {
		if i < len(dividend) {
			remainder[i] = new(big.Int).Set(dividend[i])
		} else {
			remainder[i] = new(big.Int)
		}
	}
	return
}
