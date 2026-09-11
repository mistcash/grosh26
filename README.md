# grosh26

Groth16-in-Groth16 recursion for [gnark](https://github.com/Consensys/gnark): verify a BN254 Groth16 proof inside another Groth16 circuit, and on-chain.

The in-circuit pairing costs ~38% fewer constraints and ~36% less prover time than gnark's, at the price of two extra verifier pairings. See [How it works](#how-it-works).

**Unaudited — research / testnet use only.**

## Benchmark

Pairing-only lower bound (`lib/profile` `groth16Sim` vs gnark), plus the full recursion example (`examples/recursion`, Poseidon 2→1 inner → outer):

| Phase/Metric | gnark | grosh26 | Delta |
| :--- | :--- | :--- | :--- |
| R1CS Constraints | 791,462 | 492,028 | −37.8% |
| Committed Variables | 589,289 | 399,398 | −32.2% |
| BSB22 Commitments | 1 | 3 | 2 extra verifier pairings |
| Witness Solve Time | 240.7 ms | 153.6 ms | −36.2% |
| Compile Time | 1,101 ms | 626.9 ms | −43.1% |
| **Groth16 Phases** |  |  |  |
| kSum recomb (shared) | 168,603 | 168,603 | 0 |
| G1 checks ×2 (shared) | 1,276 | 1,276 | 0 |
| Bs ladder+subgroup | 107,888 | 108,642 | −754 |
| Loop+tail+previous | 513,695 | 213,507 | 300,188 |


```
R1CS Constraints (lower is better)
gnark       [████████████████████] 791,462
grosh26     [████████████░░░░░░░░] 492,028  (-37.8%)

Solve Time (lower is better)
gnark       [████████████████████] ~240 ms
grosh26     [████████████░░░░░░░░] ~155 ms  (~-36%)
```

¹ Solve times are indicative (they jitter ±20% run to run). Hardware: Apple M3 Pro 36gb

Re-run locally for your numbers:
`go test ./... -run=^$ -bench=. -benchtime=1x -v`.


## What does Grosh26 do

- Wraps one proof into one outer proof
- Generates on chain verifier for recursion
- Grosh26 uses a bigger on-chain verifier (3 BSB22 commitment pairings instead of 1) for a cheaper prover.

Most optimised version is implementated in `lib/profile/groth16sim_test.go`.

If you need nested recursion (outer-of-outer) or non-BN254 curves, see [Further work](#further-work).

## Quickstart

```sh
go test ./examples/recursion/ -run TestGroth16Verifier -v
```

Template: `examples/recursion` (inner: `examples/poseidon`, Poseidon 2→1 preimage). Copy it.

```go
import (
    "github.com/consensys/gnark-crypto/ecc"
    groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/mistcash/grosh26/std/recursion"
)

vk, _ := recursion.NewVerifyingKey(innerVK.(*groth16bn254.VerifyingKey))
// Same vk for compile and witness: the inner VK is a compile-time constant.
outerCcs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(vk))

assignment := recursion.NewCircuit(vk)
assignment.Proof, _ = recursion.ValueOfProof(innerProof) // no BSB22 commitments in v0.1
assignment.PublicWitness = recursion.ValueOfPublicWitness(innerPublicInputs)
witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
// Setup / Prove / Verify from here are stock gnark.
```

On-chain verifier (required — gnark's generator supports 1 commitment, ring circuits draw 3; full flow in `lib/solidity/solidity_test.go`):

```go
import (
    "github.com/consensys/gnark/backend"
    "github.com/consensys/gnark/backend/groth16"
    gnarksolidity "github.com/consensys/gnark/backend/solidity"
    "github.com/mistcash/grosh26/lib/solidity"
)

proof, _ := groth16.Prove(ccs, pk, witness,
    gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
// outerVK: this outer circuit's native verifying key from Setup.
solidity.ExportSolidity(outerVK.(*groth16bn254.VerifyingKey), out)
calldata := solidity.MarshalSolidity(proof.(*groth16bn254.Proof))
```

## Further work

- **Infinite recursion:** write the outer verifier to handle inner BSB22 commitments (including their PoK checks), so an outer proof can itself be recursed. Open question under investigation: whether the ~38% prover saving per level still outweighs the extra verifier pairings as depth grows.
- **Variable VK:** Allow variable circuit verification.
- **Aggregation:** verify multiple inner proofs in one outer (shared Miller loop / batched check) for larger savings. Not yet implemented.

## Requirements

- Go 1.26.2
- `solc` on `PATH` only for `lib/solidity` on-chain tests (skipped without it)

gnark comes via the `replace` in `go.mod` (pinned `mistcash/tiny-gnark` fork). No other setup.

## How it works

BN254 pairing over a polynomial ring `F_p[x]/(x^12 − 18x^6 + 82)` with deferred product checks (one batched Schwartz–Zippel identity), following [On Proving Pairings](https://eprint.iacr.org/2024/640.pdf). Only `e(A,B)` runs the full Miller loop; `e(α,β)` is folded in as a constant previous value and `e(L,γ)`, `e(C,δ)` use precomputed lines. Details: `std/ring_bn254`, `std/polyring`.

## Layout

| path | what |
| --- | --- |
| `std/recursion` | outer Groth16 verifier — start here |
| `std/ring_bn254` | ring pairing + `PairingCheck` |
| `std/polyring` | deferred product checker |
| `lib/solidity` | multi-commitment verifier exporter |
| `examples/poseidon`, `examples/recursion` | inner statement + end-to-end flow |
| `lib/profile`, `lib/bench` | pairing bench + compile-and-solve helper |

## Tests

```sh
go test ./...
./lib/profile/pprof-groth16sim.sh  # profiles + full bench sweep → bench/groth16-delta.txt, needs graphviz `dot`
```

## License

Apache-2.0, see [LICENSE](LICENSE).
