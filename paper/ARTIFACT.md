# Artifact guide

Implementation for:

> Shramee Srivastav. *Pairing Proofs and Polynomial Ring Toolkit.*
> IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), 2027.

Maps the paper to the code and explains why numbers here differ from the
published ones. Usage and layout: [README](../README.md).

## Two repositories

The paper was measured on a gnark fork that predates two security fixes. That
fork is frozen so the published numbers stay reproducible.

| | [`ppprt`](https://github.com/mistcash/ppprt) | `polyring` (this repo) |
|---|---|---|
| Use it to | reproduce Table 7 as published | use and extend the technique |
| gnark | fork, upstream merged to `c05c6a8` (3 Aug 2026) | v0.16.4 via pinned [`tiny-gnark`](https://github.com/mistcash/tiny-gnark) |
| Sound | **no** ([why](#why-the-numbers-move)) | yes, unaudited |
| Shape | inside gnark's `std/math/emulated` | standalone Go module |
| Extras | — | recursive Groth16 verifier (BN254, BLS12-381 inner), multi-commitment Solidity verifier, on-chain test |

## Requirements

- Go 1.26.8
- `solc` (0.8.24+) for the on-chain test; skipped without it
- Optional: graphviz `dot` for `lib/profile/pprof-groth16.sh`

## Running it

Wall-clock on an Apple M3 Pro (36 GB).

| Command | What | Time |
|---|---|---|
| `go test -short ./...` | all but the on-chain test | ~25 s |
| `go test ./examples/recursion/ -run TestOuterOnChain -v` | real outer proof, deployed and verified on a simulated EVM; prints gas | ~2 min |
| `go test ./paper/ -run TestTable7 -v` | [Table 7 on patched gnark](#table-7-on-patched-gnark) | ~45 s |
| `go test ./... -run='^$' -bench=. -benchtime=1x -v` | constraint counts, gnark vs polyring, both curves | ~1 min |

## Paper to code

| Paper | Code |
|---|---|
| Operation polynomials, Miller loop (§4) | `std/ringpairing/pairing.go` (`millerLoopLines`, `PairingCheck`) |
| Per-curve lines, twist, loop counter | `std/ring_bn254/pairing.go`, `std/ring_bls12381/pairing.go` |
| Residue witness, final exponentiation (§4.2.4) | `std/ringpairing/pairing.go`, hints in `std/ring_*/hints.go` |
| Two-round protocol, quotient batching (§5) | `std/polyring/field_polyring.go`: `performDeferredRingChecks` |
| API, hints, deferred reduction (§6.2, 6.3.1, 6.5) | `std/polyring/field_polyring.go` |
| BN254 modulus `x¹² − 18x⁶ + 82`, `modEvalFn` (§6.1) | `std/ringpairing/ring.go`: `newRing` |

The API hangs off a `PolyRingChecker` rather than gnark's `emulated.Field`.
The §6.4 example:

```go
prc := polyring.NewPolyRingChecker[emulated.BN254Fp](api) // before any other emulated field
modPoly := prc.MakePoly(82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0, 1)
ring := prc.NewPolyRingCheck(modPoly, nil)
res, _ := prc.MulPolyRings(ring, A, B, C) // (A·B·C) mod modPoly, checked when Define returns
acc := prc.NewPolyRingAccumulator(ring, targetDeg)
acc.Mul(A).Mul(B).Sqr() // enqueue (A·B)²
rem := acc.Eval()        // one deferred check for the chain
```

Create the checker first: gnark runs deferred callbacks in registration order,
and its checks emit range checks.

## Results

### Table 7 as published: `ppprt`

See [ppprt's README](https://github.com/mistcash/ppprt#reproducing-table-7).

| | Paper | Re-run |
|---|---|---|
| BN254 SCS constraints | 1,592,440 → 1,035,550 (35.0%) | 1,604,279 → 1,035,645 (35.4%) |
| BN254 Fq committed | 571,125 → 269,616 (52.8%) | 606,104 → 269,656 (55.5%) |
| BN254 R1CS constraints | 491,447 → 316,167 (35.7%) | 495,810 → 316,181 (36.2%) |
| BLS12-381 SCS constraints | 1,784,247 → 1,191,105 (33.2%) | 1,779,202 → 1,191,256 (33.0%) |
| BLS12-381 Fq committed | 660,160 → 300,104 (54.5%) | 673,107 → 300,166 (55.4%) |
| BLS12-381 R1CS constraints | 545,510 → 368,434 (32.5%) | 542,925 → 368,461 (32.1%) |

"This Work" reproduces within 0.02%; the baseline within 1%, since upstream
gnark moved before `ppprt`'s merge.

### Why the numbers move

Two gnark advisories landed after `ppprt`'s last merge:

- [GHSA-3mvx-pp85-pm65](https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65)
  (critical, fixed v0.16.2): unchecked carry polynomial in emulated deferred
  checks let a prover satisfy a false multiplication.
- [GHSA-fwf3-jmp7-gmrj](https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj)
  (medium): G2 on-twist check in the Miller loop was discarded.

The carry range checks grow **both** columns. gnark's own Table 7 pairing costs
1.61–1.78× more on v0.16.4 (gnark column below; ppprt on upstream v0.16.4
matches to the digit).

### Table 7 on patched gnark

[`paper/table7_test.go`](table7_test.go) rebuilds ppprt's circuit
(e(P₁,Q₁)·e(P₂,Q₂)·e(P₃,Q₃) = 1, Q₁ and Q₂ fixed, Q₃ from the witness) and runs
gnark's and polyring's pairing on both curves and constraint systems. It fails
if any count drifts. Counts are exact; times and memory are one run and move a
few points between runs.

| Metric | gnark | polyring | Reduction | Paper |
| :--- | ---: | ---: | ---: | ---: |
| **BN254 – SCS** | | | | |
| Nb constraints | 2,834,581 | 1,739,215 | 38.6% | 35.0% |
| Nb committed vars¹ | 599,158 | 377,345 | 37.0% | 52.8% |
| Compile time | 1,628 ms | 915 ms | 43.8% | 43.6% |
| Compile memory | 2.34 GiB | 1.37 GiB | 41.5% | 38.3% |
| Solve time | 279 ms | 166 ms | 40.4% | 41.9% |
| Solve memory | 618 MiB | 317 MiB | 48.8% | 48.0% |
| **BN254 – R1CS** | | | | |
| Nb constraints | 791,907 | 493,120 | 37.7% | 35.7% |
| Nb committed vars¹ | 592,907 | 404,792 | 31.7% | 52.8% |
| Compile time | 1,543 ms | 907 ms | 41.2% | 40.5% |
| Compile memory | 2.63 GiB | 1.50 GiB | 42.8% | 38.8% |
| Solve time | 285 ms | 171 ms | 40.0% | 39.4% |
| Solve memory | 273 MiB | 138 MiB | 49.3% | 34.9% |
| **BLS12-381 – SCS** | | | | |
| Nb constraints | 3,164,858 | 2,011,453 | 36.4% | 33.2% |
| Nb committed vars¹ | 670,229 | 428,291 | 36.1% | 54.5% |
| Compile time | 1,808 ms | 1,075 ms | 40.5% | 36.9% |
| Compile memory | 2.42 GiB | 1.55 GiB | 36.1% | 34.5% |
| Solve time | 311 ms | 190 ms | 39.0% | 38.0% |
| Solve memory | 634 MiB | 331 MiB | 47.8% | 21.5% |
| **BLS12-381 – R1CS** | | | | |
| Nb constraints | 881,274 | 573,283 | 34.9% | 32.5% |
| Nb committed vars¹ | 664,065 | 471,596 | 29.0% | 54.5% |
| Compile time | 1,684 ms | 1,024 ms | 39.2% | 38.3% |
| Compile memory | 2.88 GiB | 1.78 GiB | 38.4% | 35.1% |
| Solve time | 326 ms | 197 ms | 39.5% | 33.7% |
| Solve memory | 282 MiB | 196 MiB | 30.5% | 48.8% |

Constraint reductions beat the paper's by 2.0–3.6 points.

¹ Variables gnark's Groth16 backend commits to (`bench.NbCommittedVars`). The
paper's "Fq committed" counts values passed to `api.Commit` via a counter only
`ppprt` has, so it is reproduced there.

### This repository's benchmarks

Full Groth16 verifier inside a BN254 Groth16 circuit, over a real MiMC inner
proof. R1CS counts, exact; times jitter 20%+. Per-phase breakdown in the
[README](../README.md#benchmark).

| Circuit | Inner curve | gnark | polyring | Reduction |
|---|---|---|---|---|
| Groth16 verifier (`lib/profile`) | BN254 | 791,400 | 491,043 | 38.0% |
| | BLS12-381 | 979,700 | 677,317 | 30.9% |
| Two-pair check, witness G2 (`std/ringpairing`) | BN254 | 736,686 | 510,588 | 30.7% |
| | BLS12-381 | 917,190 | 720,136 | 21.5% |

On-chain, polyring proofs carry three BSB22 commitments instead of one:
`verifyProof` costs ~460k gas vs ~359k for gnark.

### Table 6 (Cairo)

Measured in [Garaga](https://github.com/keep-starknet-strange/garaga); not part
of this artifact.
