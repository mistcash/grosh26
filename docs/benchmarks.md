# Benchmarks

Every number on this page is measured by a test in this repository, and every
one of them can be reproduced with a command.

## The setup

The circuit under test is the outer verifier (`std/recursion`) over a genuine
MiMC inner proof (`examples/mimc`). Two things are held fixed and one is
varied:

- **Fixed:** the inner circuit, the inner statement, the inner verifying key,
  and the outer field (BN254 in every case).
- **Varied:** the pairing implementation. `lib/gnarkpairing` runs the same
  outer circuit over gnark's in-circuit pairing
  (`sw_bn254.Pairing.PairingCheck` / `sw_bls12381.PairingCheck`); polyring
  runs it over the ring pairing.

So the difference between the two columns is the cost of the ring pairing and
nothing else.

## Constraints and timings

```sh
go test ./... -run=^$ -bench=. -benchtime=1x -v
```

| Inner curve | Metric | gnark | polyring | Delta |
| :--- | :--- | ---: | ---: | ---: |
| **BN254** | R1CS constraints | 791,400 | 492,105 | −37.8% |
| | Committed variables | 589,535 | 399,735 | −32.2% |
| | BSB22 commitments | 1 | 3 | +2 |
| | Witness solve time | 320 ms | 189 ms | −41.0% |
| | Compile time | 1,750 ms | 1,040 ms | −40.6% |
| **BLS12-381** | R1CS constraints | 979,700 | 677,317 | −30.9% |
| | Committed variables | 731,178 | 539,891 | −26.2% |
| | BSB22 commitments | 1 | 3 | +2 |
| | Witness solve time | 364 ms | 232 ms | −36.3% |
| | Compile time | 2,230 ms | 1,527 ms | −31.5% |

The constraint counts are exact and reproduce to the digit on the same gnark
version. The timings are indicative: they move by 20% or more between runs,
and the delta moves with them. Treat the constraint counts as the claim and
the timings as a hint about its sign.

Hardware for the numbers above: Apple M3 Pro 36gb, 20 iterations, median of
3 runs.

## Per-phase breakdown

The outer verifier is not one thing, so the total is broken down by the phase
of `AssertProof` that pays for it.

`kSum`, the two G1 checks and the `Bs` ladder are measured directly, from
small isolating circuits that each do one of them. `loop+tail+previous` — the
Miller accumulation, the final exponentiation or residue tail, and the
folded-in `e(α,β)` — is whatever the measured phases do not account for, so
the phases sum to the total by construction.

**BN254**

| Phase | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| Total | 791,400 | 492,105 | 299,295 |
| kSum recomb | 17,352 | 17,352 | 0 |
| G1 checks ×2 | 1,276 | 1,276 | 0 |
| Bs ladder+subgroup | 116,352 | 120,066 | −3,714 |
| Loop+tail+previous | 656,420 | 353,411 | 303,009 |

**BLS12-381**

| Phase | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| Total | 979,700 | 677,317 | 302,383 |
| kSum recomb | 23,486 | 23,486 | 0 |
| G1 checks ×2 | 117,871 | 117,871 | 0 |
| Bs ladder+subgroup | 144,459 | 144,509 | −50 |
| Loop+tail+previous | 693,884 | 391,451 | 302,433 |

The reading is simple: the entire saving comes from the loop, the tail and
the folded-in previous value — the parts of the pairing that gnark does in
𝔽p¹² and polyring does in the ring. The `Bs` ladder is slightly *more*
expensive in polyring, by 3,714 constraints on BN254, because the ring's line
embeddings are not free. The K-sum and the G1 checks are identical, as they
should be: they do not touch the pairing.

The BLS12-381 G1 checks cost 117,871 constraints against BN254's 1,276,
because the BLS12-381 base field emulated over BN254 is much wider. That is
the price of a BLS12-381 inner proof, paid by both pairings alike.

## On-chain cost

The prover gets cheaper; the verifier gets bigger. Measured on a simulated
EVM, over a real inner proof, with the outer verifier on BN254:

```sh
go test ./examples/recursion/ -run TestOuterOnChain -v
```

| Metric | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| R1CS constraints | 791,400 | 492,105 | −37.8% |
| BSB22 commitments | 1 | 3 | +2 |
| Proof size | 384 B | 512 B | +128 B |
| Contract size | 7,407 B | 10,394 B | +2,987 B |
| `verifyProof` gas | 358,571 | 459,994 | +101,423 (+28.3%) |

The +101,423 gas is the two extra pairing pairs the contract has to check:
polyring's outer proof carries three BSB22 commitments, so the contract
checks three commitment proofs of knowledge where gnark's checks one.

Both contracts come from polyring's generator, so the comparison isolates the
commitment count rather than the generator. The gas is the simulated
backend's, not a mainnet quote.

## Profiling

```sh
./lib/profile/pprof-groth16.sh
```

Writes gnark's constraint and operation profiles and a full benchmark sweep
to `lib/profile/profiles/`. Needs graphviz's `dot` for the PDF steps. The
script's per-benchmark profiling block is currently commented out; the sweep
at the end works as is.
