package polyring

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mistcash/polynomial-ring-toolkit/internal/limbs"
)

// fullChallengeLimbs returns the number of nbBits-wide limbs needed to hold a
// native field element at full width, with no truncation: the number
// NativeToEmulated decomposes into, and the width the deferred ring check's
// off-circuit RLC hint must mask a challenge to for the two to agree.
func (prc *PolyRingChecker[T]) fullChallengeLimbs() int {
	nbBits := int(prc.fp.BitsPerLimb())
	return prc.api.Compiler().FieldBitLen()/nbBits + 1
}

// NativeToEmulated decomposes each native field var into FieldBitLen/nbBits
// limbs and returns it as a full-width Element[T], with no truncation: per
// the Fiat-Shamir construction from eprint 2024/640, the Schwartz-Zippel
// challenge is the verifier-side commitment randomness itself, used in full.
func (prc *PolyRingChecker[T]) NativeToEmulated(v ...frontend.Variable) ([]*emulated.Element[T], error) {
	nbBits := int(prc.fp.BitsPerLimb())
	nbLimbs := prc.fullChallengeLimbs()
	nbFieldLimbs := int(prc.fp.NbLimbs())
	if nbLimbs > nbFieldLimbs {
		// the emulated field is too narrow to hold a native element, so the
		// challenge could only be carried across truncated -- which is exactly
		// what this construction must not do.
		return nil, fmt.Errorf("polyring: a native element needs %d limbs of %d bits, the emulated field holds %d: the challenge would have to be truncated", nbLimbs, nbBits, nbFieldLimbs)
	}
	hintInputs := make([]frontend.Variable, 0, 2+len(v))
	hintInputs = append(hintInputs, nbBits, nbLimbs)
	hintInputs = append(hintInputs, v...)
	ret, err := prc.api.NewHint(splitNativeToLimbsHint, nbLimbs*len(v), hintInputs...)
	if err != nil {
		return nil, err
	}
	elements := make([]*emulated.Element[T], len(v))
	for i := range elements {
		// An element carries exactly NbLimbs limbs, which is not in general the
		// number a native element decomposes into. Any limb above the
		// decomposition is zero by construction, and a constant zero needs no
		// range check or recomposition term of its own.
		elLimbs := make([]frontend.Variable, nbFieldLimbs)
		copy(elLimbs, ret[i*nbLimbs:(i+1)*nbLimbs])
		for j := nbLimbs; j < nbFieldLimbs; j++ {
			elLimbs[j] = 0
		}
		// packLimbs performs range checks on limbs
		elements[i] = prc.f.NewElement(elLimbs)

		rebuildEl := elLimbs[0]
		placeValue := big.NewInt(1)
		for j := 1; j < nbLimbs; j++ {
			placeValue.Lsh(placeValue, uint(nbBits))
			rebuildEl = prc.api.Add(rebuildEl, prc.api.Mul(elLimbs[j], placeValue))
		}
		// assert correct decomposition
		prc.api.AssertIsEqual(rebuildEl, v[i])
	}
	return elements, nil
}

func splitNativeToLimbsHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return fmt.Errorf("splitNativeToLimbs: not enough inputs")
	}

	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	outptr := 0
	for ptr := 2; ptr < len(inputs); ptr++ {
		nativeEl := inputs[ptr]
		if err := limbs.Decompose(nativeEl, uint(nbBits), outputs[outptr:outptr+nbLimbs]); err != nil {
			return fmt.Errorf("decompose result[%d]: %w", ptr-2, err)
		}
		outptr += nbLimbs
	}

	return nil
}
