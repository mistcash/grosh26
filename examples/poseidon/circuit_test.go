package poseidon_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"

	"github.com/mistcash/grosh26/examples/poseidon"
)

func TestCircuitSolved(t *testing.T) {
	assert := test.NewAssert(t)

	assignment, err := poseidon.AssignRandom()
	assert.NoError(err)
	assert.NoError(test.IsSolved(&poseidon.Circuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestCircuitRejectsWrongDigest makes sure the check is not vacuous: a digest
// poseidon does not produce from (A, B) must not solve.
func TestCircuitRejectsWrongDigest(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b fr.Element
	_, err := a.SetRandom()
	assert.NoError(err)
	_, err = b.SetRandom()
	assert.NoError(err)

	assignment, err := poseidon.Assign(&a, &b)
	assert.NoError(err)

	wrong, ok := assignment.Digest.(*big.Int)
	assert.True(ok)
	wrong = new(big.Int).Add(wrong, big.NewInt(1))
	assignment.Digest = wrong

	assert.Error(test.IsSolved(&poseidon.Circuit{}, assignment, ecc.BN254.ScalarField()))
}
