package fields_bn254

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e12Convert struct {
	A E12
}

func (circuit *e12Convert) Define(api frontend.API) error {
	e := NewExt12(api)
	tower := e.ToTower(&circuit.A)
	expected := e.FromTower(tower)
	e.AssertIsEqual(expected, &circuit.A)
	return nil
}

func TestConvertFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a bn254.E12
	_, _ = a.SetRandom()

	witness := e12Convert{A: FromE12(&a)}

	assert.NoError(test.IsSolved(&e12Convert{}, &witness, ecc.BN254.ScalarField()))
}

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e12Add{A: FromE12(&a), B: FromE12(&b), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Add{}, &witness, ecc.BN254.ScalarField()))
}

type e12Mul struct {
	A, B, C E12
}

func (circuit *e12Mul) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

// TestMulFp12Ring exercises the polynomial ring path: the product comes out of
// a hint and the deferred check has to accept it.
func TestMulFp12Ring(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12Mul{A: FromE12(&a), B: FromE12(&b), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField()))
}

// TestMulFp12RingWrongProduct checks the deferred ring check actually rejects a
// product that isn't one.
func TestMulFp12RingWrongProduct(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c, one bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)
	one.SetOne()
	c.Add(&c, &one) // off by one

	witness := e12Mul{A: FromE12(&a), B: FromE12(&b), C: FromE12(&c)}

	assert.Error(test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField()))
}

type e12MulDirect struct {
	A, B, C E12
}

func (circuit *e12MulDirect) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.MulDirect(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

// TestMulFp12Direct pins the ring result against the coefficient-wise product.
func TestMulFp12Direct(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12MulDirect{A: FromE12(&a), B: FromE12(&b), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12MulDirect{}, &witness, ecc.BN254.ScalarField()))
}

type e12Square struct {
	A, C E12
}

func (circuit *e12Square) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	// the direct square has to agree with the ring one
	e.AssertIsEqual(e.SquareDirect(&circuit.A), &circuit.C)
	return nil
}

func TestSquareFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e12Square{A: FromE12(&a), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Square{}, &witness, ecc.BN254.ScalarField()))
}

type e12Inverse struct {
	A, C E12
}

func (circuit *e12Inverse) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestInverseFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e12Inverse{A: FromE12(&a), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField()))
}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e12Div{A: FromE12(&a), B: FromE12(&b), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Div{}, &witness, ecc.BN254.ScalarField()))
}

type e12Frobenius struct {
	A, C E12
}

func (circuit *e12Frobenius) Define(api frontend.API) error {
	e := NewExt12(api)
	e.AssertIsEqual(e.Frobenius(&circuit.A), &circuit.C)
	return nil
}

func TestFrobeniusFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Frobenius(&a)

	witness := e12Frobenius{A: FromE12(&a), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Frobenius{}, &witness, ecc.BN254.ScalarField()))
}

const testExponent = 65537

type e12Exp struct {
	A, C E12
}

func (circuit *e12Exp) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.ExpConst(&circuit.A, big.NewInt(testExponent))
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

// TestExpFp12 exercises the ring accumulator: seventeen square-and-multiply
// steps get batched into a handful of deferred ring checks.
func TestExpFp12(t *testing.T) {
	assert := test.NewAssert(t)

	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Exp(a, big.NewInt(testExponent))

	witness := e12Exp{A: FromE12(&a), C: FromE12(&c)}

	assert.NoError(test.IsSolved(&e12Exp{}, &witness, ecc.BN254.ScalarField()))
}
