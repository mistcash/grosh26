# polyring

Groth16-in-Groth16 recursion for [gnark](https://github.com/Consensys/gnark): verify a BN254 or BLS12-381 Groth16 proof inside a BN254 Groth16 circuit, and on-chain.

The in-circuit pairing costs ~31–38% fewer constraints and ~34–44% less witness solve time than gnark's, at the price of two extra verifier pairings. See [How it works](#how-it-works).

**Unaudited — research / testnet use only.**

## Paper

The maintained implementation of *Pairing Proofs and Polynomial Ring Toolkit* (S. Srivastav, IACR TCHES 2027). The paper's numbers were measured on an earlier gnark fork, kept frozen at [mistcash/ppprt](https://github.com/mistcash/ppprt) to reproduce them; it predates two gnark soundness fixes this repository carries. [paper/ARTIFACT.md](paper/ARTIFACT.md) maps the paper to the code and explains how the numbers relate.

## Benchmark

The outer verifier circuit (`std/recursion`) over a genuine MiMC inner proof, with gnark's pairing vs polyring's ring pairing. Same circuit, same statement; only the pairing check differs. Outer field is BN254 in every case.

| Inner curve | Metric | gnark | polyring | Delta |
| :--- | :--- | ---: | ---: | ---: |
| **BN254** | R1CS constraints | 791,400 | 491,043 | −38.0% |
| | Committed variables | 589,535 | 398,959 | −32.3% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 340 ms | 223 ms | −34.4% |
| | Compile time | 1,618 ms | 923 ms | −43.0% |
| **BLS12-381** | R1CS constraints | 979,700 | 677,317 | −30.9% |
| | Committed variables | 731,178 | 539,891 | −26.2% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 462 ms | 258 ms | −44.2% |
| | Compile time | 2,199 ms | 1,470 ms | −33.2% |

```
R1CS constraints (lower is better)
BN254      gnark    [███████████████░░░░░]   791,400
           polyring [█████████░░░░░░░░░░░]   491,043  (-38.0%)
BLS12-381  gnark    [████████████████████]  979,700
           polyring [██████████████░░░░░░]   677,317  (-30.9%)
```

¹ Solve times are indicative (they jitter ±20% run to run). Hardware: Apple M3 Pro 36gb

### Groth16 phases

R1CS constraints per verifier phase. kSum, the G1 checks and the Bs ladder (on-twist and subgroup check included: Bs needs no separate `AssertIsOnG2`) are measured from small isolating circuits; loop+tail+previous (Miller accumulation, final exponentiation/residue tail, folded-in e(α,β)) is the remainder, so phases sum to the total. Delta is gnark − polyring. The ladder row is a marginal (witness `Bs` minus the same check with precomputed lines), so it also picks up batching effects from the rest of the circuit; in an isolating ladder circuit, polyring's ladder is 1,348 constraints below gnark's.

**BN254**

| Phase | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| Total | 791,400 | 491,043 | 300,357 |
| kSum recomb | 17,352 | 17,352 | 0 |
| G1 checks ×2 | 1,276 | 1,276 | 0 |
| Bs ladder+subgroup | 116,352 | 119,004 | −2,652 |
| Loop+tail+previous | 656,420 | 353,411 | 303,009 |

**BLS12-381**

| Phase | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| Total | 979,700 | 677,317 | 302,383 |
| kSum recomb | 23,486 | 23,486 | 0 |
| G1 checks ×2 | 117,871 | 117,871 | 0 |
| Bs ladder+subgroup | 144,459 | 144,509 | −50 |
| Loop+tail+previous | 693,884 | 391,451 | 302,433 |

Re-run locally for your numbers (`lib/profile`, plus the bare two-pair check in `std/ringpairing`):
`go test ./... -run=^$ -bench=. -benchtime=1x -v`.


## What does Polyring do

- Wraps one proof into one outer proof
- Generates on chain verifier for recursion
- Inner proofs over BN254 or BLS12-381, one generic verifier circuit for both
- Polyring uses a bigger on-chain verifier (3 BSB22 commitment pairings instead of 1) for a cheaper prover.

If you need nested recursion (outer-of-outer), see [Further work](#further-work).

## Quickstart

```sh
go test ./examples/recursion/ -run TestGroth16Verifier -v
```

Template: `examples/recursion` (inner: `examples/mimc`, MiMC preimage, on either curve). Copy it.

```go
import (
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/mistcash/polyring/std/recursion"
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
    "github.com/mistcash/polyring/lib/solidity"
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

- Go 1.26.8
- `solc` on `PATH` only for `lib/solidity` on-chain tests (skipped without it)

gnark comes via the `replace` in `go.mod` (pinned `mistcash/tiny-gnark` fork). No other setup.

## How it works

Pairing over the polynomial ring `F_p[w]/(w^12 − 2ξ₀w^6 + ξ₀² + 1)` — `x^12 − 18x^6 + 82` for BN254, `x^12 − 2x^6 + 2` for BLS12-381 — with deferred product checks (one batched Schwartz–Zippel identity), following [On Proving Pairings](https://eprint.iacr.org/2024/640.pdf). Only `e(A,B)` runs the full Miller loop; `e(α,β)` is folded in as a constant previous value and `e(L,γ)`, `e(C,δ)` use precomputed lines. The Miller loop driver and residue check are shared (`std/ringpairing`); each curve package owns its twist — G2 ladder, line shape, subgroup check, loop schedule — on gnark's own 𝔽p² arithmetic (`std/ring_bn254`, `std/ring_bls12381`). Details there and in `std/polyring`.

## Layout

| path | what |
| --- | --- |
| `std/recursion` | outer Groth16 verifier, generic over the inner curve — start here |
| `std/ringpairing` | ring pairing core: ring, Miller loop driver, `PairingCheck`, the `Curve` interface |
| `std/ring_bn254`, `std/ring_bls12381` | per-curve ring pairing: twist, G2 ladder, hints, `NewPairing` |
| `std/polyring` | deferred product checker |
| `lib/solidity` | multi-commitment verifier exporter |
| `examples/mimc`, `examples/recursion` | inner statement + end-to-end flow |
| `lib/profile`, `lib/bench` | Groth16 bench (both curves, gnark vs polyring) + compile-and-solve helper |
| `paper` | the paper's Table 7 re-measured here, gnark vs polyring, see [paper/ARTIFACT.md](paper/ARTIFACT.md) |

## Tests

```sh
go test ./...
./lib/profile/pprof-groth16.sh  # profiles + full bench sweep → bench/groth16-delta.txt, needs graphviz `dot`
```

## License

Apache-2.0, see [LICENSE](LICENSE).
