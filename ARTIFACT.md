# Artifact guide

This repository is the maintained implementation for:

> Shramee Srivastav. *Pairing Proofs and Polynomial Ring Toolkit.*
> IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES), 2027.

This guide maps the paper to the code, says where each of its results is
reproduced, and explains why numbers measured here differ from the published
ones. Usage and layout are in the [README](README.md).

## Two repositories

The paper's numbers were measured on a gnark fork that predates two gnark
security fixes. That fork is kept frozen so the published numbers stay
reproducible; this repository carries the same technique on patched gnark.

| | [`ppprt`](https://github.com/mistcash/ppprt) | `polyring` (this repo) |
|---|---|---|
| Use it to | reproduce Table 7 as published | use, extend and evaluate the technique |
| gnark | fork, upstream merged up to `c05c6a8` (3 Aug 2026) | v0.16.4 with the fixes, via the pinned [`tiny-gnark`](https://github.com/mistcash/tiny-gnark) fork |
| Sound | **no** — see [below](#why-the-numbers-move) | yes, unaudited |
| Shape | toolkit inside gnark's `std/math/emulated` | standalone Go module |
| Beyond the paper | — | recursive Groth16 verifier for BN254 and BLS12-381 inner proofs, multi-commitment Solidity verifier, on-chain test |

## Requirements

- Go 1.26.8 (from `go.mod`)
- `solc` on `PATH` for the on-chain test only; CI uses 0.8.24, 0.8.36 also works.
  Without it the on-chain test is skipped.
- Optional: graphviz `dot`, only for `lib/profile/pprof-groth16.sh`

gnark and every other dependency come through `go.mod`; nothing else to set up.

## Running it

Times are wall-clock on an Apple M3 Pro (36 GB).

| Command | What it does | Time |
|---|---|---|
| `go test -short ./...` | all tests except the on-chain one | ~25 s |
| `go test ./examples/recursion/ -run TestOuterOnChain -v` | proves the outer circuit for real with both pairings, deploys the generated verifier to a simulated EVM, verifies, and rejects tampered commitments; prints the on-chain cost table | ~2 min |
| `go test ./paper/ -run TestTable7 -v` | Table 7 on patched gnark, gnark vs polyring: prints the table with its reduction column, fails if a count moved; see [below](#table-7-on-patched-gnark-paper) | ~45 s |
| `go test ./... -run='^$' -bench=. -benchtime=1x -v` | constraint counts for the Groth16 verifier and the two-pair check, gnark vs polyring, both curves | ~1 min |

## Paper to code

| Paper | Code |
|---|---|
| Operation polynomials, Miller loop steps (Section 4) | `std/ringpairing/pairing.go` (`millerLoopLines`, `PairingCheck`) |
| Per-curve lines, twist and loop counter | `std/ring_bn254/pairing.go`, `std/ring_bls12381/pairing.go` |
| Residue witness and final exponentiation (Section 4.2.4) | `std/ringpairing/pairing.go`, with gnark's residue hints in `std/ring_*/hints.go` |
| Two-round protocol, quotient batching (Section 5) | `std/polyring/field_polyring.go`: `performDeferredRingChecks` |
| `NewPolyRingCheck`, `MulPolyRings`, `ToCommit`, `PolyRingAccumulator` (Section 6.3.1) | `std/polyring/field_polyring.go` |
| `polyRingMulHint`, `quotientsRLCHint` (Section 6.2) | `std/polyring/field_polyring.go` |
| `InnerProductNoReduce`, deferred reduction (Section 6.5) | `std/polyring/field_polyring.go` |
| BN254 modulus `x¹² − 18x⁶ + 82` with `modEvalFn` (Section 6.1) | `std/ringpairing/ring.go`: `newRing` |

The API is the paper's, but it hangs off a `PolyRingChecker` instead of gnark's
`emulated.Field`, because this repository is a module of its own rather than a
patch to gnark. The Section 6.4 example reads:

```go
prc := polyring.NewPolyRingChecker[emulated.BN254Fp](api) // before any other emulated field
modPoly := prc.MakePoly(82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0, 1)
ring := prc.NewPolyRingCheck(modPoly, nil)
res, _ := prc.MulPolyRings(ring, A, B, C) // (A·B·C) mod modPoly, checked when Define returns
acc := prc.NewPolyRingAccumulator(ring, targetDeg)
acc.Mul(A).Mul(B).Sqr() // enqueue (A·B)², nothing multiplied yet
rem := acc.Eval()        // one deferred check for the whole chain
```

The checker has to be created before anything else in the circuit creates an
emulated field: its checks emit range checks, and gnark runs deferred callbacks
in registration order.

## Results

### Table 7 (gnark, 3-pairing product check): reproduced in `ppprt`

Follow [ppprt's README](https://github.com/mistcash/ppprt#reproducing-table-7).
It gives the commands for both columns, how each benchmark line maps to a table
row, and what a re-run gives. In short, against the upstream gnark that `ppprt`
is merged on:

| | Paper | Re-run |
|---|---|---|
| BN254 SCS constraints | 1,592,440 → 1,035,550 (35.0%) | 1,604,279 → 1,035,645 (35.4%) |
| BN254 Fq committed | 571,125 → 269,616 (52.8%) | 606,104 → 269,656 (55.5%) |
| BN254 R1CS constraints | 491,447 → 316,167 (35.7%) | 495,810 → 316,181 (36.2%) |
| BLS12-381 SCS constraints | 1,784,247 → 1,191,105 (33.2%) | 1,779,202 → 1,191,256 (33.0%) |
| BLS12-381 Fq committed | 660,160 → 300,104 (54.5%) | 673,107 → 300,166 (55.4%) |
| BLS12-381 R1CS constraints | 545,510 → 368,434 (32.5%) | 542,925 → 368,461 (32.1%) |

The "This Work" column reproduces to within 0.02%; the baseline to within 1% on
constraints, because upstream gnark moved between the paper's run and the commit
`ppprt` merged.

### Why the numbers move

Two gnark advisories were published after `ppprt`'s last upstream merge:

- [GHSA-3mvx-pp85-pm65](https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65)
  (critical, fixed in v0.16.2): the carry polynomial in emulated-field deferred
  checks came from a hint and was never range-checked, so a malicious prover
  could satisfy a false multiplication. Every emulated pairing sits on those
  checks.
- [GHSA-fwf3-jmp7-gmrj](https://github.com/Consensys/gnark/security/advisories/GHSA-fwf3-jmp7-gmrj)
  (medium): the on-twist check on G2 inputs to the Miller loop was computed and
  discarded.

The carry range checks add constraints to every emulated multiplication, so they
grow **both** columns: gnark's own pairing as much as the ring pairing. On the
Table 7 circuit, gnark's pairing on gnark v0.16.4 costs 1.61–1.78× what it did
in the paper:

| Table 7 circuit, gnark's pairing | Paper | gnark v0.16.4 |
|---|---|---|
| BN254 SCS constraints | 1,592,440 | 2,834,581 |
| BN254 R1CS constraints | 491,447 | 791,907 |
| BLS12-381 SCS constraints | 1,784,247 | 3,164,858 |
| BLS12-381 R1CS constraints | 545,510 | 881,274 |

Two independent runs give the v0.16.4 column to the digit: ppprt's own benchmark
file on upstream v0.16.4 ([ppprt's baseline steps](https://github.com/mistcash/ppprt#baseline-column)
with `git checkout v0.16.4`), and the gnark column of `paper/` below.

### Table 7 on patched gnark: `paper/`

```sh
go test ./paper/ -run TestTable7 -v
```

[`paper/table7_test.go`](paper/table7_test.go) builds ppprt's Table 7 circuit
field for field: the 3-pairing check e(P₁,Q₁)·e(P₂,Q₂)·e(P₃,Q₃) = 1, with Q₁
and Q₂ fixed (precomputed lines) and Q₃ from the witness, compiled over the
curve's own scalar field. It runs it with gnark's pairing and with polyring's,
on both curves and both constraint systems, all on the gnark this module builds
with. For each it checks that the instance solves, benchmarks compile and
solve, and prints Table 7 with a reduction column. It fails if any constraint
or committed-variable count differs from the one recorded in the test.

Counts are exact. Times and memory are one run on an Apple M3 Pro; repeated
runs move the time reductions by a few points.

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

Every constraint reduction is 2.0–3.6 points larger than the paper's.

¹ Read from gnark's compiled commitment info (`bench.NbCommittedVars`), the
same count as the [README benchmark](README.md#benchmark). The paper's "Nb Fq
Committed" is a different count: the values passed to `api.Commit`, from a
counter `ppprt` adds to gnark, so it is reproduced there, not here.

### What this repository measures

The benchmarks in this tree measure what polyring is for: a full Groth16
verifier inside a BN254 Groth16 circuit, over a real MiMC inner proof. These are
R1CS counts; see the [README](README.md#benchmark) for the per-phase breakdown.

| Circuit | Inner curve | gnark | polyring | Reduction |
|---|---|---|---|---|
| Groth16 verifier (`lib/profile`) | BN254 | 791,400 | 491,043 | 38.0% |
| | BLS12-381 | 979,700 | 677,317 | 30.9% |
| Two-pair check, both G2 from the witness (`std/ringpairing`) | BN254 | 736,686 | 510,588 | 30.7% |
| | BLS12-381 | 917,190 | 720,136 | 21.5% |

The on-chain test adds the cost on the verifier's side: polyring's proofs carry
three BSB22 commitments instead of one, so `verifyProof` costs ~460k gas
against ~359k for gnark's.

Reading the benchmark output:

- `[BENCH] <name> <n> r1cs constraints <m> vars over <k> commitments`:
  constraint counts are exact and reproduce to the digit. `vars` counts the
  variables gnark's Groth16 backend commits to, range checker included. That is not
  the paper's "Fq committed", which counts the values passed to `api.Commit`.
- Compile and solve times jitter by 20% or more from run to run.

### Table 6 (Cairo)

Table 6 was measured in [Garaga](https://github.com/keep-starknet-strange/garaga),
which deploys the technique for CairoVM on Starknet. It is not part of this
artifact.
