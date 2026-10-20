// Package paper re-measures the paper's gnark benchmark (Table 7 of
// "Pairing Proofs and Polynomial Ring Toolkit", TCHES 2027) on this
// repository: gnark's pairing against polyring's ring pairing, on the patched
// gnark this module builds with. See ARTIFACT.md.
//
//	go test ./paper/ -run TestTable7 -v
//
// prints Table 7 for both curves with the reduction column, and fails if a
// constraint or committed-variable count moved from the one recorded here.
package paper

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/mistcash/polyring/lib/bench"
	"github.com/mistcash/polyring/std/ring_bls12381"
	"github.com/mistcash/polyring/std/ring_bn254"
	"github.com/mistcash/polyring/std/ringpairing"
)

// checker is the one method both pairings share in this benchmark.
type checker[F emulated.FieldParams, G2El any] interface {
	PairingCheck(P []*ringpairing.G1Affine[F], Q []*G2El) error
}

// ringChecker adapts the ring pairing, whose PairingCheck also takes an
// optional previous Miller loop value, to [checker].
type ringChecker[F emulated.FieldParams, G2El, GtEl any] struct {
	*ringpairing.Pairing[F, G2El, GtEl]
}

func (r ringChecker[F, G2El, GtEl]) PairingCheck(P []*ringpairing.G1Affine[F], Q []*G2El) error {
	return r.Pairing.PairingCheck(P, Q, nil)
}

// table7Circuit is the circuit of ppprt's g16_simulation_test.go, field for
// field: e(P1,Q1)·e(P2,Q2)·e(P3,Q3) == 1, the pairing workload of a Groth16
// verification, with Q1 and Q2 fixed (precomputed lines, assigned through the
// witness) and Q3 a plain witness point. No on-curve checks, as in ppprt.
type table7Circuit[F emulated.FieldParams, G2El any] struct {
	In1G1, In2G1, In3G1 ringpairing.G1Affine[F]
	In1G2, In2G2, In3G2 G2El

	// newPairing picks the pairing under test. It runs first in Define: the
	// ring pairing has to exist before anything else creates an emulated field.
	newPairing func(frontend.API) (checker[F, G2El], error)
}

func (c *table7Circuit[F, G2El]) Define(api frontend.API) error {
	pr, err := c.newPairing(api)
	if err != nil {
		return err
	}
	return pr.PairingCheck(
		[]*ringpairing.G1Affine[F]{&c.In1G1, &c.In2G1, &c.In3G1},
		[]*G2El{&c.In1G2, &c.In2G2, &c.In3G2},
	)
}

// curveCase is one curve's half of Table 7.
type curveCase[F emulated.FieldParams, G2El any] struct {
	name string
	// field is the native field the circuit is compiled over, as in ppprt:
	// BN254's scalar field for BN254, BLS12-381's for BLS12-381.
	field *big.Int
	// placeholder is the circuit-side value of a fixed G2 point.
	placeholder func() G2El
	// assignment is a satisfying instance, built as ppprt builds it.
	assignment func() *table7Circuit[F, G2El]
	gnark      func(frontend.API) (checker[F, G2El], error)
	ring       func(frontend.API) (checker[F, G2El], error)
}

func bn254Case() curveCase[emulated.BN254Fp, sw_bn254.G2Affine] {
	return curveCase[emulated.BN254Fp, sw_bn254.G2Affine]{
		name:        "BN254",
		field:       ecc.BN254.ScalarField(),
		placeholder: sw_bn254.NewG2AffineFixedPlaceholder,
		assignment: func() *table7Circuit[emulated.BN254Fp, sw_bn254.G2Affine] {
			_, _, p, q := bn254.Generators()
			var p1, p2, p3 bn254.G1Affine
			var q1, q2, q3 bn254.G2Affine
			p1.Double(&p)
			q1.Double(&q)
			p2.Neg(&p1)
			q2.Set(&q)
			p3.Set(&p)
			q3.Neg(&q1)
			return &table7Circuit[emulated.BN254Fp, sw_bn254.G2Affine]{
				In1G1: sw_bn254.NewG1Affine(p1), In1G2: sw_bn254.NewG2AffineFixed(q1),
				In2G1: sw_bn254.NewG1Affine(p2), In2G2: sw_bn254.NewG2AffineFixed(q2),
				In3G1: sw_bn254.NewG1Affine(p3), In3G2: sw_bn254.NewG2Affine(q3),
			}
		},
		gnark: func(api frontend.API) (checker[emulated.BN254Fp, sw_bn254.G2Affine], error) {
			return sw_bn254.NewPairing(api)
		},
		ring: func(api frontend.API) (checker[emulated.BN254Fp, sw_bn254.G2Affine], error) {
			pr, err := ring_bn254.NewPairing(api)
			return ringChecker[emulated.BN254Fp, sw_bn254.G2Affine, sw_bn254.GTEl]{pr}, err
		},
	}
}

func bls12381Case() curveCase[emulated.BLS12381Fp, sw_bls12381.G2Affine] {
	return curveCase[emulated.BLS12381Fp, sw_bls12381.G2Affine]{
		name:        "BLS12-381",
		field:       ecc.BLS12_381.ScalarField(),
		placeholder: sw_bls12381.NewG2AffineFixedPlaceholder,
		assignment: func() *table7Circuit[emulated.BLS12381Fp, sw_bls12381.G2Affine] {
			_, _, p, q := bls12381.Generators()
			var p1, p2, p3 bls12381.G1Affine
			var q1, q2, q3 bls12381.G2Affine
			p1.Double(&p)
			q1.Double(&q)
			p2.Neg(&p1)
			q2.Set(&q)
			p3.Set(&p)
			q3.Neg(&q1)
			return &table7Circuit[emulated.BLS12381Fp, sw_bls12381.G2Affine]{
				In1G1: sw_bls12381.NewG1Affine(p1), In1G2: sw_bls12381.NewG2AffineFixed(q1),
				In2G1: sw_bls12381.NewG1Affine(p2), In2G2: sw_bls12381.NewG2AffineFixed(q2),
				In3G1: sw_bls12381.NewG1Affine(p3), In3G2: sw_bls12381.NewG2Affine(q3),
			}
		},
		gnark: func(api frontend.API) (checker[emulated.BLS12381Fp, sw_bls12381.G2Affine], error) {
			return sw_bls12381.NewPairing(api)
		},
		ring: func(api frontend.API) (checker[emulated.BLS12381Fp, sw_bls12381.G2Affine], error) {
			pr, err := ring_bls12381.NewPairing(api)
			return ringChecker[emulated.BLS12381Fp, sw_bls12381.G2Affine, sw_bls12381.GTEl]{pr}, err
		},
	}
}

// backends are Table 7's two constraint systems, in its order.
var backends = []struct {
	name       string
	newBuilder frontend.NewBuilder
}{
	{"SCS", scs.NewBuilder[constraint.U64]},
	{"R1CS", r1cs.NewBuilder[constraint.U64]},
}

// result is one column of one Table 7 block.
type result struct {
	constraints, committed int
	compileNs, compileB    int64
	solveNs, solveB        int64
}

// measure compiles a fresh circuit from newCircuit, checks that w solves it,
// and benchmarks compiling and solving it. The circuit is rebuilt for every
// compile: the pairings cache api-bound state in Define.
func measure(t *testing.T, field *big.Int, newBuilder frontend.NewBuilder, newCircuit func() frontend.Circuit, w witness.Witness) result {
	t.Helper()
	ccs, err := frontend.Compile(field, newBuilder, newCircuit())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccs.Solve(w); err != nil {
		t.Fatalf("solve: %v", err)
	}
	compile := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := frontend.Compile(field, newBuilder, newCircuit()); err != nil {
				b.Fatal(err)
			}
		}
	})
	solve := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
	return result{
		constraints: ccs.GetNbConstraints(),
		committed:   bench.NbCommittedVars(ccs),
		compileNs:   compile.NsPerOp(), compileB: compile.AllocedBytesPerOp(),
		solveNs: solve.NsPerOp(), solveB: solve.AllocedBytesPerOp(),
	}
}

// want holds the exact counts, per curve, backend and pairing. They are
// deterministic: a change here means the circuit changed, and the numbers in
// ARTIFACT.md have to be re-measured with it.
var want = map[string]int{
	"BN254/SCS/gnark/constraints":         2834581,
	"BN254/SCS/polyring/constraints":      1739215,
	"BN254/SCS/gnark/committed":           599158,
	"BN254/SCS/polyring/committed":        377345,
	"BN254/R1CS/gnark/constraints":        791907,
	"BN254/R1CS/polyring/constraints":     493120,
	"BN254/R1CS/gnark/committed":          592907,
	"BN254/R1CS/polyring/committed":       404792,
	"BLS12-381/SCS/gnark/constraints":     3164858,
	"BLS12-381/SCS/polyring/constraints":  2011453,
	"BLS12-381/SCS/gnark/committed":       670229,
	"BLS12-381/SCS/polyring/committed":    428291,
	"BLS12-381/R1CS/gnark/constraints":    881274,
	"BLS12-381/R1CS/polyring/constraints": 573283,
	"BLS12-381/R1CS/gnark/committed":      664065,
	"BLS12-381/R1CS/polyring/committed":   471596,
}

// TestTable7 measures Table 7 for both curves and logs it as a Markdown table.
// It takes about a minute: the timing rows are real benchmarks.
func TestTable7(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmarks every circuit; run without -short")
	}
	var out strings.Builder
	out.WriteString("\n| Metric | gnark | polyring | Reduction |\n| :--- | ---: | ---: | ---: |\n")
	t.Run("bn254", func(t *testing.T) { table7(t, bn254Case(), &out) })
	t.Run("bls12-381", func(t *testing.T) { table7(t, bls12381Case(), &out) })
	t.Log(out.String())
}

func table7[F emulated.FieldParams, G2El any](t *testing.T, cc curveCase[F, G2El], out *strings.Builder) {
	w, err := frontend.NewWitness(cc.assignment(), cc.field)
	if err != nil {
		t.Fatal(err)
	}
	circuit := func(newPairing func(frontend.API) (checker[F, G2El], error)) func() frontend.Circuit {
		return func() frontend.Circuit {
			return &table7Circuit[F, G2El]{In1G2: cc.placeholder(), In2G2: cc.placeholder(), newPairing: newPairing}
		}
	}
	for _, be := range backends {
		g := measure(t, cc.field, be.newBuilder, circuit(cc.gnark), w)
		p := measure(t, cc.field, be.newBuilder, circuit(cc.ring), w)
		for _, c := range []struct {
			metric string
			got    [2]int
		}{
			{"constraints", [2]int{g.constraints, p.constraints}},
			{"committed", [2]int{g.committed, p.committed}},
		} {
			for i, pairing := range []string{"gnark", "polyring"} {
				key := cc.name + "/" + be.name + "/" + pairing + "/" + c.metric
				if c.got[i] != want[key] {
					t.Errorf("%s = %d, want %d", key, c.got[i], want[key])
				}
			}
		}
		fmt.Fprintf(out, "| **%s – %s** | | | |\n", cc.name, be.name)
		row(out, "Nb constraints", float64(g.constraints), float64(p.constraints), "%.0f")
		row(out, "Nb committed vars", float64(g.committed), float64(p.committed), "%.0f")
		row(out, "Compile time (ms)", float64(g.compileNs)/1e6, float64(p.compileNs)/1e6, "%.2f")
		row(out, "Compile memory (GiB)", float64(g.compileB)/(1<<30), float64(p.compileB)/(1<<30), "%.2f")
		row(out, "Solve time (ms)", float64(g.solveNs)/1e6, float64(p.solveNs)/1e6, "%.2f")
		row(out, "Solve memory (MiB)", float64(g.solveB)/(1<<20), float64(p.solveB)/(1<<20), "%.2f")
	}
}

// row writes one table row, the reduction as Table 7 reports it.
func row(out *strings.Builder, metric string, gnark, polyring float64, format string) {
	reduction := 100 * (gnark - polyring) / gnark
	fmt.Fprintf(out, "| %s | "+format+" | "+format+" | %.1f%% |\n", metric, gnark, polyring, reduction)
}
