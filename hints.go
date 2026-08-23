package emulated

import (
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetPolyRingHints()...)
}

// GetPolyRingHints returns all the hint functions used by the polynomial ring
// checker. They are registered globally in this package's init, so a caller
// only needs this when configuring the solver with an explicit hint set.
//
// The name is not the usual GetHints because this package dot-imports gnark's
// emulated package, which exports a GetHints of its own.
func GetPolyRingHints() []solver.Hint {
	return []solver.Hint{
		polyRingMulHint,
		quotientsRLCHint,
		splitNativeToLimbsHint,
		identityHint,
	}
}
