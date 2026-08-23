package fq12

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"github.com/mistcash/grosh26/std/fields_bn254"
)

func TestCircuitSolved(t *testing.T) {
	assert := test.NewAssert(t)

	assignment, err := AssignRandom()
	assert.NoError(err)

	assert.NoError(test.IsSolved(&Circuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestCircuitRejectsWrongResult checks the circuit is not vacuously satisfied:
// a public Y that isn't X^Exponent has to fail.
func TestCircuitRejectsWrongResult(t *testing.T) {
	assert := test.NewAssert(t)

	var x, y bn254.E12
	_, err := x.SetRandom()
	assert.NoError(err)
	y.Exp(x, big.NewInt(Exponent+1))

	assignment := &Circuit{X: fields_bn254.FromE12(&x), Y: fields_bn254.FromE12(&y)}

	assert.Error(test.IsSolved(&Circuit{}, assignment, ecc.BN254.ScalarField()))
}

// TestGroth16RoundTrip runs the whole default-gnark pipeline over the circuit:
// compile, setup, prove and verify, with the commitment challenges derived the
// way the Solidity verifier does it.
func TestGroth16RoundTrip(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	require.NoError(t, err)

	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)

	assignment, err := AssignRandom()
	require.NoError(t, err)

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err := fullWitness.Public()
	require.NoError(t, err)

	proof, err := groth16.Prove(ccs, pk, fullWitness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	require.NoError(t, err)

	require.NoError(t, groth16.Verify(proof, vk, publicWitness, solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)))
}
