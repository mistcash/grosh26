package recursion_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/stretchr/testify/require"
)

func TestGroth16VerifierBLS12381(t *testing.T) {
	testGroth16Verifier[emparams.BLS12381Fp, emparams.BLS12381Fr, sw_bls12381.G2Affine, sw_bls12381.GTEl](t, attacks{
		curve: ecc.BLS12_381,
		withAr: func(p groth16.Proof) groth16.Proof {
			return blsProof(p, func(c *groth16bls12381.Proof) { blsSetG1(&c.Ar, 42) })
		},
		withKrs: func(p groth16.Proof) groth16.Proof {
			return blsProof(p, func(c *groth16bls12381.Proof) { blsSetG1(&c.Krs, 42) })
		},
		withBsOffTwist: func(_ testing.TB, p groth16.Proof) groth16.Proof {
			return blsProof(p, func(c *groth16bls12381.Proof) { c.Bs.X.A0.Add(&c.Bs.X.A0, new(blsfp.Element).SetOne()) })
		},
		withBsOutsideG2: func(t testing.TB, p groth16.Proof) groth16.Proof {
			return blsProof(p, func(c *groth16bls12381.Proof) { c.Bs = blsTwistPointOutsideG2(t) })
		},
		withVKOffTwist: blsVKOffTwist,
	})
}

// blsProof returns a copy of proof with f applied.
func blsProof(proof groth16.Proof, f func(*groth16bls12381.Proof)) groth16.Proof {
	c := *proof.(*groth16bls12381.Proof)
	f(&c)
	return &c
}

// blsSetG1 sets p to [k]G1.
func blsSetG1(p *bls12381.G1Affine, k int64) {
	_, _, g1, _ := bls12381.Generators()
	p.ScalarMultiplication(&g1, big.NewInt(k))
}

// blsVKOffTwist returns a copy of vk with the named G2 point moved off the twist.
func blsVKOffTwist(vk groth16.VerifyingKey, name string) groth16.VerifyingKey {
	c := *vk.(*groth16bls12381.VerifyingKey)
	pt := map[string]*bls12381.G2Affine{"beta": &c.G2.Beta, "gamma": &c.G2.Gamma, "delta": &c.G2.Delta}[name]
	pt.X.A0.Add(&pt.X.A0, new(blsfp.Element).SetOne())
	return &c
}

// blsTwistPointOutsideG2 returns a point on the twist y² = x³ + b' that is not in
// the prime-order subgroup: the twist's cofactor is huge, so a random point
// on it is outside G2 but for a negligible chance. b' = y² - x³ comes from the
// G2 generator.
func blsTwistPointOutsideG2(t testing.TB) bls12381.G2Affine {
	t.Helper()
	_, _, _, g2 := bls12381.Generators()
	var b, x3 bls12381.E2
	b.Square(&g2.Y)
	x3.Square(&g2.X).Mul(&x3, &g2.X)
	b.Sub(&b, &x3)

	for range 100 {
		var p bls12381.G2Affine
		_, err := p.X.SetRandom()
		require.NoError(t, err)
		var rhs bls12381.E2
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
	return bls12381.G2Affine{}
}
