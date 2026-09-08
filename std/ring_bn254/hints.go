package ring_bn254

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// The three hints below are gnark's, and unexported. Their maths -- inverting
// an 𝔽p¹² element, and finding the residue witness of a pairing check, with
// or without a previous Miller loop value folded in -- is not something to
// keep a second copy of, so they are picked out of the exported hint lists by
// name instead. All are registered with the solver by gnark's own package
// init.
var (
	inverseE12Hint                = gnarkHint(fields_bn254.GetHints(), "inverseE12Hint")
	pairingCheckHint              = gnarkHint(sw_bn254.GetHints(), "pairingCheckHint")
	millerLoopAndCheckFinalExpHint = gnarkHint(sw_bn254.GetHints(), "millerLoopAndCheckFinalExpHint")
)

// gnarkHint returns the hint named name from hints. It panics when there is no
// such hint, which would mean gnark renamed or dropped it.
func gnarkHint(hints []solver.Hint, name string) solver.Hint {
	for _, h := range hints {
		if hintName := solver.GetHintName(h); strings.HasSuffix(hintName, "."+name) {
			return h
		}
	}
	panic(fmt.Sprintf("ring_bn254: gnark no longer exposes a hint named %q", name))
}
