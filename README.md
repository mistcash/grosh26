# grosh26

Go library for [gnark](https://github.com/Consensys/gnark) (BN254) that does two things: verifies a Groth16 proof **inside** another circuit, and exports a Solidity verifier for circuits whose proofs carry **more than one** BSB22 commitment. Together: a proof of a proof, verifiable on-chain.

- In-circuit pairing check (`std/ring_bn254`) evaluates F_p¹² products in F_p[x]/(x¹² − 18x⁶ + 82) with hinted products batched into one deferred identity, instead of reducing every product.
- Outer verifier circuit (`std/recursion`) checks the Groth16 identity `e(A,B)·e(α,β)⁻¹·e(L,γ)⁻¹·e(C,δ)⁻¹ = 1` as one `PairingCheck`: one full pairing, two fixed-Q pairs, one previous Miller value.
- Solidity generator (`lib/solidity`) handles any number of commitments. gnark's own generator does not. Setup, proving, and off-chain verification stay gnark's.

> Active development lives in `lib/profile`: its `groth16Sim` (ring) /
> `groth16SimGnark` (gnark) circuits are the most optimised Groth16
> verification shape in either toolkit, and the functional frontier moves
> there first.

**Unaudited.** Do not use with real value without an audit. See `docs/review-spec.md` for the soundness arguments and open items.

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
| `docs/review-spec.md` | protocol + soundness notes for reviewers |

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
`std/recursion` costs more. `pprof-groth16sim.sh` runs that
bench with Go CPU/mem profiles plus gnark constraint/operation profiles, then
sweeps the other benches for counts. Requires graphviz `dot` for the PDF steps.

```sh
./lib/profile/pprof-groth16sim.sh
# BENCHTIME=10x  per-benchmark time (default: 10x)
# OUTDIR=lib/profile/profiles/groth16sim  output dir (default as shown)
```

Per circuit (`groth16sim-ring`, `groth16sim-gnark`) it writes Go profiles
(`*.cpu.{out,pdf}`, `*.mem.{out,pdf}`), gnark profiles (`*.pprof`,
`*.constraints.pdf`, `*.operations.pdf`) and the bench log (`*.bench.log`),
plus a `bench/` summary sweep of the other benches. Profile artifacts under
`lib/profile/profiles/` are gitignored; the committed snapshot is
[`bench/groth16-delta.txt`](bench/groth16-delta.txt) — regenerate it with the
script rather than hand-editing.

## License

Apache-2.0, see [LICENSE](LICENSE).
