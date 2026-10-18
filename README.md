# grosh26

Groth16-in-Groth16 recursion for [gnark](https://github.com/Consensys/gnark): verify a BN254 or BLS12-381 Groth16 proof inside a BN254 Groth16 circuit, and on-chain.

The in-circuit pairing costs ~28–38% fewer constraints and ~40% less witness solve time than gnark's, at the price of two extra verifier pairings. See [How it works](#how-it-works).

**Unaudited — research / testnet use only.**

## Benchmark

The outer verifier circuit (`std/recursion`) over a genuine Poseidon 2→1 inner proof, with gnark's pairing vs grosh26's ring pairing. Same circuit, same statement; only the pairing check differs. Outer field is BN254 in every case.

| Inner curve | Metric | gnark | grosh26 | Delta |
| :--- | :--- | ---: | ---: | ---: |
| **BN254** | R1CS constraints | 791,462 | 491,067 | −38.0% |
| | Committed variables | 589,289 | 398,561 | −32.4% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 351 ms | 202 ms | −42.5% |
| | Compile time | 1,742 ms | 928 ms | −46.7% |
| **BLS12-381** | R1CS constraints | 1,085,538 | 781,479 | −28.0% |
| | Committed variables | 813,210 | 620,627 | −23.7% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 442 ms | 261 ms | −40.9% |
| | Compile time | 2,470 ms | 1,419 ms | −42.5% |

```
R1CS constraints (lower is better)
BN254      gnark    [███████████████░░░░░]   791,462
           grosh26  [█████████░░░░░░░░░░░]   491,067  (-38.0%)
BLS12-381  gnark    [████████████████████] 1,085,538
           grosh26  [██████████████░░░░░░]   781,479  (-28.0%)
```

¹ Solve times are indicative (they jitter ±20% run to run). Hardware: Apple M3 Pro 36gb

### Groth16 phases

R1CS constraints per verifier phase. kSum, the G1 checks and the Bs ladder (on-twist and subgroup check included: Bs needs no separate `AssertIsOnG2`) are measured from small isolating circuits; loop+tail+previous (Miller accumulation, final exponentiation/residue tail, folded-in e(α,β)) is the remainder, so phases sum to the total. Delta is gnark − grosh26.

**BN254**

| Phase | gnark | grosh26 | Delta |
| :--- | ---: | ---: | ---: |
| Total | 791,462 | 491,067 | 300,395 |
| kSum recomb | 17,654 | 17,654 | 0 |
| G1 checks ×2 | 1,276 | 1,276 | 0 |
| Bs ladder+subgroup | 116,352 | 120,593 | −4,241 |
| Loop+tail+previous | 656,180 | 351,544 | 304,636 |

**BLS12-381**

| Phase | gnark | grosh26 | Delta |
| :--- | ---: | ---: | ---: |
| Total | 1,085,538 | 781,479 | 304,059 |
| kSum recomb | 24,206 | 24,206 | 0 |
| G1 checks ×2 | 246,429 | 246,429 | 0 |
| Bs ladder+subgroup | 144,459 | 144,508 | −49 |
| Loop+tail+previous | 670,444 | 366,336 | 304,108 |

Re-run locally for your numbers (`lib/profile`, plus the bare two-pair check in `std/ringpairing`):
`go test ./... -run=^$ -bench=. -benchtime=1x -v`.


## What does Grosh26 do

- Wraps one proof into one outer proof
- Generates on chain verifier for recursion
- Inner proofs over BN254 or BLS12-381, one generic verifier circuit for both
- Grosh26 uses a bigger on-chain verifier (3 BSB22 commitment pairings instead of 1) for a cheaper prover.

If you need nested recursion (outer-of-outer), see [Further work](#further-work).

## Quickstart

```sh
go test ./examples/recursion/ -run TestGroth16Verifier -v
```

Template: `examples/recursion` (inner: `examples/poseidon`, Poseidon 2→1 preimage, on either curve). Copy it.

```go
import (
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/mistcash/grosh26/std/recursion"
)

// innerVK, innerProof, innerPublic: a native BN254 or BLS12-381 Groth16 key,
// proof and public witness (no BSB22 commitments in v0.1).
vk, _ := recursion.NewVerifyingKey(innerVK)
// Same vk for compile and witness: the inner VK is a compile-time constant.
// BLS12-381 inner proofs: NewBLS12381Circuit, otherwise identical.
outerCcs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewBN254Circuit(vk))

assignment := recursion.NewBN254Circuit(vk)
_ = assignment.Assign(innerProof, innerPublic)
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

Pairing over the polynomial ring `F_p[w]/(w^12 − 2ξ₀w^6 + ξ₀² + 1)` — `x^12 − 18x^6 + 82` for BN254, `x^12 − 2x^6 + 2` for BLS12-381 — with deferred product checks (one batched Schwartz–Zippel identity), following [On Proving Pairings](https://eprint.iacr.org/2024/640.pdf). Only `e(A,B)` runs the full Miller loop; `e(α,β)` is folded in as a constant previous value and `e(L,γ)`, `e(C,δ)` use precomputed lines. One generic Miller loop, residue check and G2 ladder serve both curves; each curve contributes a small spec (`std/ringpairing/bn254.go`, `bls12381.go`). Details: `std/ringpairing`, `std/polyring`.

## Layout

| path | what |
| --- | --- |
| `std/recursion` | outer Groth16 verifier, generic over the inner curve — start here |
| `std/ringpairing` | ring pairing + `PairingCheck`, BN254 and BLS12-381 |
| `std/polyring` | deferred product checker |
| `lib/solidity` | multi-commitment verifier exporter |
| `examples/poseidon`, `examples/recursion` | inner statement + end-to-end flow |
| `lib/profile`, `lib/bench` | Groth16 bench (both curves, gnark vs grosh26) + compile-and-solve helper |

## Tests

```sh
go test ./...
./lib/profile/pprof-groth16.sh  # profiles + full bench sweep → bench/groth16-delta.txt, needs graphviz `dot`
```

## License

Apache-2.0, see [LICENSE](LICENSE).
