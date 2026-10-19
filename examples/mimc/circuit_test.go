package mimc_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/mistcash/polyring/examples/mimc"
)

var curves = []ecc.ID{ecc.BN254, ecc.BLS12_381}

func TestCircuitSolved(t *testing.T) {
	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			assignment, err := mimc.AssignRandom(curve)
			assert.NoError(err)
			assert.NoError(test.IsSolved(&mimc.Circuit{}, assignment, curve.ScalarField()))
		})
	}
}

// TestCircuitRejectsWrongDigest makes sure the check is not vacuous: a digest
// MiMC does not produce from (A, B) must not solve.
func TestCircuitRejectsWrongDigest(t *testing.T) {
	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			assignment, err := mimc.AssignRandom(curve)
			assert.NoError(err)

			wrong, ok := assignment.Digest.(*big.Int)
			assert.True(ok)
			assignment.Digest = new(big.Int).Add(wrong, big.NewInt(1))

			assert.Error(test.IsSolved(&mimc.Circuit{}, assignment, curve.ScalarField()))
		})
	}
}

func TestProve(t *testing.T) {
	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			_, _, _, err := mimc.Prove(curve)
			test.NewAssert(t).NoError(err)
		})
	}
}
