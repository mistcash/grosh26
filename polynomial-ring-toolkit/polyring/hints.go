package polyring

import (
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all the hint functions used by the polynomial ring checker.
// They are registered globally in this package's init, so a caller only needs
// this when configuring the solver with an explicit hint set.
func GetHints() []solver.Hint {
	return []solver.Hint{
		polyRingMulHint,
		quotientsRLCHint,
		splitNativeToLimbsHint,
	}
}
