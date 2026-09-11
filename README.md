# grosh26

Prover-friendly Groth16 recursion for [gnark](https://github.com/Consensys/gnark). Runs a two-round (non) interactive proof to verify batches of $\mathbb{F}_p[x]/(x^{12} - 18x^6 + 82)$ operations, reducing provers overhead by over 35% while adding two extra pairings for the verifier.

### Benchmark Comparison

> Evaluated on `groth16Sim` vs `groth16SimGnark`. In standard Groth16 with BSB22, each additional commitment requires an extra pairing check.

| Metric | standard `gnark` | `grosh26` (`std/polyring`) | Delta |
| :--- | :--- | :--- | :--- |
| **R1CS Constraints** | 791,462 | **492,028** | **−37.8%** |
| **Committed Variables** | 589,289 | **399,398** | **−32.2%** |
| **BSB22 Commitments** | 1 | **3** | **2 extra verifier pairings** |
| **Witness Solve Time** | 240.7 ms | **153.6 ms** | **−36.2%** |
| **Solve Heap Allocs** | 1,484,017 allocs | **332,655 allocs** | **−77.6%** |
| **Compile Time** | 1,101 ms | **626.9 ms** | **−43.1%** |

```
R1CS Constraints (lower is better)
gnark       [████████████████████] 791,462
grosh26     [████████████░░░░░░░░] 492,028  (-37.8%)

Solve Time (lower is better)
gnark       [████████████████████] 240.7 ms
grosh26     [████████████░░░░░░░░] 153.6 ms  (-36.2%)
```

> Active development lives in `lib/profile`: its `groth16Sim` (ring) /
> `groth16SimGnark` (gnark) circuits are the most optimised Groth16
> verification shape in either toolkit, and the functional frontier moves
> there first.

**Unaudited.** Do not use in production, audit pending.

## Requirements

- Go (see `go.mod` for the version)
- `solc` on `PATH` (or `SOLC_BIN` set) — only for the on-chain test in `lib/solidity`; it skips without one

gnark comes via the `replace` in `go.mod` (pinned `mistcash/tiny-gnark` fork, same module path). No setup needed beyond `go build` / `go test`.

## Use

### 1. Verify an inner Groth16 proof in-circuit

Template: `examples/recursion` (inner: `examples/poseidon`, a Poseidon 2→1 preimage proof). The inner verifying key is a compile-time constant, not a witness.

```go
import (
    "github.com/consensys/gnark-crypto/ecc"
    groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/mistcash/grosh26/std/recursion"
)

// innerVK: inner circuit's native verifying key (groth16.VerifyingKey from Setup).
vk, err := recursion.NewVerifyingKey(innerVK.(*groth16bn254.VerifyingKey))
// Same vk for compile and witness.
outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(vk))

assignment := recursion.NewCircuit(vk)
assignment.Proof, err = recursion.ValueOfProof(innerProof) // *groth16bn254.Proof, no commitments (v0.1)
assignment.PublicWitness = recursion.ValueOfPublicWitness(innerPublicInputs)
witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
// groth16.Setup / Prove / Verify from here are stock gnark.
```

Constraint: inner circuits carrying BSB22 commitments are rejected (`NewVerifyingKey` / `ValueOfProof` error). The outer proof itself draws three commitments (two ring + one range checker).

### 2. Export an on-chain verifier

Use this instead of gnark's generator whenever the circuit draws more than one commitment (all ring-pairing circuits do). Prove with the Solidity target so prover and contract agree:

```go
import (
    "github.com/consensys/gnark/backend"
    "github.com/consensys/gnark/backend/groth16"
    groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
    gnarksolidity "github.com/consensys/gnark/backend/solidity"
    "github.com/mistcash/grosh26/lib/solidity"
)

proof, err := groth16.Prove(ccs, pk, witness,
    gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
// vk: this circuit's native verifying key.
err = solidity.ExportSolidity(vk.(*groth16bn254.VerifyingKey), out /* io.Writer */)
// Calldata for verifyProof: solidity.MarshalSolidity(proof.(*groth16bn254.Proof))
```

## Layout

| path | what |
| --- | --- |
| `std/polyring` | deferred `Fp[x]/(mod)` product checker |
| `std/ring_bn254` | ring-based BN254 `Ext12`, Miller loop, `PairingCheck` |
| `std/recursion` | outer Groth16 verifier circuit |
| `lib/solidity` | multi-commitment Solidity exporter + calldata packing |
| `lib/bench`, `lib/soltest` | compile-and-solve bench helper; simulated-EVM deploy helper |
| `lib/profile` | ring-vs-gnark comparison bench + `pprof-groth16sim.sh` profiling run |
| `examples/poseidon` | inner circuit (demo statement) |
| `examples/recursion` | end-to-end recursion flow (copy this) |

## Tests

```sh
go test ./...
go test -bench=. -run=^$ -benchtime=1x ./std/ring_bn254/ ./examples/recursion/  # constraint counts
```

### Profiling the pairing (ring vs gnark)

`lib/profile` runs the same Groth16-identity statement through both pairings
for a like-for-like constraint comparison — and that statement is the most
optimised Groth16 verification shape each toolkit can express: single public
input (`kSum = Public·K1 + K0`), γ and δ sharing one fixed G2, `e(α,β)` folded
in as a previous Miller value (`groth16Sim` for the ring, `groth16SimGnark`
for gnark). Treat its counts as the lower bound; the real outer circuit in
`std/recursion` costs more.

`pprof-groth16sim.sh` runs that bench with Go CPU/mem profiles plus gnark
constraint/operation profiles, then sweeps the other benches for counts.
Requires graphviz `dot` for the PDF steps.

```sh
./lib/profile/pprof-groth16sim.sh
# BENCHTIME=10x  per-benchmark time (default: 10x)
# OUTDIR=lib/profile/profiles/groth16sim  output dir (default as shown)
```

Per circuit (`groth16sim-ring`, `groth16sim-gnark`) it writes Go profiles
(`*.cpu.{out,pdf}`, `*.mem.{out,pdf}`), gnark profiles (`*.pprof`,
`*.constraints.pdf`, `*.operations.pdf`) and the bench log (`*.bench.log`),
plus a `bench/` summary sweep of the other benches. Profile artifacts under
`lib/profile/profiles/` are gitignored — regenerate locally, then open
interactively, e.g.:

```sh
go tool pprof -http=:8080 lib/profile/profiles/groth16sim/groth16sim-ring.cpu.out
go tool pprof -http=:8080 lib/profile/profiles/groth16sim/groth16sim-ring.pprof
```

The committed snapshot is [`bench/groth16-delta.txt`](bench/groth16-delta.txt)
— regenerate it with the script rather than hand-editing.

## License

Apache-2.0, see [LICENSE](LICENSE).
