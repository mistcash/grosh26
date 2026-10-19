package profile

// Groth16 benchmark: the outer verifier circuit (std/recursion) over a
// MiMC inner proof, for each supported inner curve, once with gnark's
// pairing and once with the ring pairing -- the same circuit and statement,
// differing only in the pairing check. Solving is part of the benchmark, so
// an unsatisfied statement fails it: this doubles as the solved test.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkprofile "github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"

	"github.com/mistcash/polyring/examples/mimc"
	"github.com/mistcash/polyring/lib/bench"
	"github.com/mistcash/polyring/lib/gnarkpairing"
	"github.com/mistcash/polyring/std/recursion"
)

// profileOnce compiles template under a gnark constraint-profile session,
// writing <dir>/<name>.pprof for the call-site PDFs. It writes nothing
// unless GNARK_PROFILE_DIR is set, so plain bench runs stay artifact-free.
func profileOnce(b *testing.B, name string, template frontend.Circuit) {
	b.Helper()
	dir := os.Getenv("GNARK_PROFILE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	prof := gnarkprofile.Start(gnarkprofile.WithPath(filepath.Join(dir, name+".pprof")))
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	prof.Stop()
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("[%s] profiled %d constraints", name, ccs.GetNbConstraints())
}

// BenchmarkGroth16 checks the Groth16 identity
// e(Ar,Bs) · e(αₙₑg,β) · e(kSum,γₙₑg) · e(Krs,δₙₑg) == 1 for a genuine inner
// proof: Bs from the witness, γₙₑg and δₙₑg carrying precomputed lines,
// e(αₙₑg,β) folded in as the previous Miller loop value and kSum recombined
// in-circuit from the public input. Each curve ends with the per-phase
// constraint breakdown, see [logPhases].
func BenchmarkGroth16(b *testing.B) {
	b.Run("bn254", benchGroth16[emparams.BN254Fp, emparams.BN254Fr, sw_bn254.G2Affine, sw_bn254.GTEl])
	b.Run("bls12-381", benchGroth16[emparams.BLS12381Fp, emparams.BLS12381Fr, sw_bls12381.G2Affine, sw_bls12381.GTEl])
}

// assignable is an outer circuit that takes an inner proof as its witness.
type assignable interface {
	frontend.Circuit
	Assign(groth16.Proof, witness.Witness) error
}

func benchGroth16[F, S emulated.FieldParams, G2El, GtEl any](b *testing.B) {
	curve, name := ecc.BN254, "bn254"
	if _, ok := any((*G2El)(nil)).(*sw_bls12381.G2Affine); ok {
		curve, name = ecc.BLS12_381, "bls12-381"
	}
	innerVK, proof, public, err := mimc.Prove(curve)
	if err != nil {
		b.Fatal(err)
	}
	vk, err := recursion.NewVerifyingKey(innerVK)
	if err != nil {
		b.Fatal(err)
	}
	for _, backend := range []struct {
		name string
		new  func() assignable
	}{
		{"gnark", func() assignable { return gnarkpairing.NewCircuit[F, S, G2El, GtEl](vk) }},
		{"polyring", func() assignable { return recursion.NewCircuit[F, S, G2El, GtEl](vk) }},
	} {
		assignment := backend.new()
		if err := assignment.Assign(proof, public); err != nil {
			b.Fatal(err)
		}
		newCircuit := func() frontend.Circuit { return backend.new() }
		profileOnce(b, "groth16-"+name+"-"+backend.name, newCircuit())
		bench.Circuit(b, newCircuit, assignment, backend.name)
	}
	logPhases[F, S, G2El, GtEl](b, name, innerVK, vk)
}
