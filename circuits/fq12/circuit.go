// Package fq12 holds the demonstration circuit: an 𝔽p¹² exponentiation
// evaluated with the polynomial ring emulation of [fields_bn254].
package fq12

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/mistcash/grosh26/std/fields_bn254"
)

// Exponent is the fixed exponent the circuit raises its secret input to. 65537
// is 17 bits, so square-and-multiply runs 16 squarings and one multiplication.
const Exponent = 65537

// Circuit proves knowledge of a secret X ∈ 𝔽p¹² whose Exponent-th power is the
// public Y, computing X^Exponent entirely through polynomial ring products in
// 𝔽p[x]/(x¹² - 18x⁶ + 82).
//
// The public part is Y's twelve emulated coefficients, four limbs each, so the
// generated verifier takes 48 public inputs.
type Circuit struct {
	X fields_bn254.E12 `gnark:",secret"`
	Y fields_bn254.E12 `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	e := fields_bn254.NewExt12(api)
	e.AssertIsEqual(e.ExpConst(&c.X, big.NewInt(Exponent)), &c.Y)
	return nil
}

// Assign builds a witness assignment for the given secret base, computing the
// public Y = x^Exponent out of circuit with gnark-crypto.
func Assign(x *bn254.E12) *Circuit {
	var y bn254.E12
	y.Exp(*x, big.NewInt(Exponent))

	return &Circuit{
		X: fields_bn254.FromE12(x),
		Y: fields_bn254.FromE12(&y),
	}
}

// AssignRandom builds a witness assignment for a random secret base.
func AssignRandom() (*Circuit, error) {
	var x bn254.E12
	if _, err := x.SetRandom(); err != nil {
		return nil, fmt.Errorf("random 𝔽p¹² element: %w", err)
	}
	return Assign(&x), nil
}
