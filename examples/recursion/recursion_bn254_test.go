package recursion_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/stretchr/testify/require"
)

func TestGroth16VerifierBN254(t *testing.T) {
	testGroth16Verifier[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl](t, attacks{
		curve: ecc.BN254,
		withAr: func(p groth16.Proof) groth16.Proof {
			return bnProof(p, func(c *groth16bn254.Proof) { bnSetG1(&c.Ar, 42) })
		},
		withKrs: func(p groth16.Proof) groth16.Proof {
			return bnProof(p, func(c *groth16bn254.Proof) { bnSetG1(&c.Krs, 42) })
		},
		withBsOffTwist: func(_ testing.TB, p groth16.Proof) groth16.Proof {
			return bnProof(p, func(c *groth16bn254.Proof) { c.Bs.X.A0.Add(&c.Bs.X.A0, new(bnfp.Element).SetOne()) })
		},
		withBsOutsideG2: func(t testing.TB, p groth16.Proof) groth16.Proof {
			return bnProof(p, func(c *groth16bn254.Proof) { c.Bs = bnTwistPointOutsideG2(t) })
		},
		withVKOffTwist: bnVKOffTwist,
	})
}

// bnProof returns a copy of proof with f applied.
func bnProof(proof groth16.Proof, f func(*groth16bn254.Proof)) groth16.Proof {
	c := *proof.(*groth16bn254.Proof)
	f(&c)
	return &c
}

// bnSetG1 sets p to [k]G1.
func bnSetG1(p *bn254.G1Affine, k int64) {
	_, _, g1, _ := bn254.Generators()
	p.ScalarMultiplication(&g1, big.NewInt(k))
}

// bnVKOffTwist returns a copy of vk with the named G2 point moved off the twist.
func bnVKOffTwist(vk groth16.VerifyingKey, name string) groth16.VerifyingKey {
	c := *vk.(*groth16bn254.VerifyingKey)
	pt := map[string]*bn254.G2Affine{"beta": &c.G2.Beta, "gamma": &c.G2.Gamma, "delta": &c.G2.Delta}[name]
	pt.X.A0.Add(&pt.X.A0, new(bnfp.Element).SetOne())
	return &c
}

// bnTwistPointOutsideG2 returns a point on the twist y² = x³ + b' that is not in
// the prime-order subgroup: the twist's cofactor is huge, so a random point
// on it is outside G2 but for a negligible chance. b' = y² - x³ comes from the
// G2 generator.
func bnTwistPointOutsideG2(t testing.TB) bn254.G2Affine {
	t.Helper()
	_, _, _, g2 := bn254.Generators()
	var b, x3 bn254.E2
	b.Square(&g2.Y)
	x3.Square(&g2.X).Mul(&x3, &g2.X)
	b.Sub(&b, &x3)

	for range 100 {
		var p bn254.G2Affine
		_, err := p.X.SetRandom()
		require.NoError(t, err)
		var rhs bn254.E2
		rhs.Square(&p.X).Mul(&rhs, &p.X).Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		p.Y.Sqrt(&rhs)
		require.True(t, p.IsOnCurve())
		require.False(t, p.IsInSubGroup())
		return p
	}
	t.Fatal("no twist point outside G2 found")
	return bn254.G2Affine{}
}
