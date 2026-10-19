# polyring

Groth16-in-Groth16 recursion for [gnark](https://github.com/Consensys/gnark): verify a BN254 or BLS12-381 Groth16 proof inside a BN254 Groth16 circuit, and on-chain.

The in-circuit pairing costs **~31–38% fewer constraints** and **~36–41% less witness solve time** than gnark's, at the price of two extra verifier pairings on chain. See [What it costs](#what-it-costs).

**Unaudited — research / testnet use only.** v0.1, pre-1.0, no releases yet.

The outer circuit is always over BN254, whichever curve the inner proof is over.

## Why you'd want this

A Groth16 verifier circuit is dominated by one thing: the pairing check. polyring
evaluates the same identity gnark does, but over a polynomial ring instead of
over 𝔽p¹², so the prover does far less work. That matters when:

- **You prove the outer proof.** Fewer constraints is less proving time, less
  setup time, less memory, and less money at a proving service that prices by
  the constraint.
- **You verify a BLS signature inside a SNARK.** The same trick applies to
  BLS signature verification, which is where the technique comes from
  ([eprint 2024/640](https://eprint.iacr.org/2024/640)).
- **You are working on recursive SNARKs.** This is a reference implementation
  of the ring-pairing approach for both BN254 and BLS12-381, with the curve
  split cleanly from the shared core.
- **You want a faster `PairingCheck`.** `lib/gnarkpairing` gives you both
  circuits from the same verifying key, so you can A/B them in your own
  project.

### When not to use it

- **You need nested recursion** (an outer proof that is itself recursively
  verified). Not implemented — see [Further work](#further-work).
- **Your inner circuit draws its own BSB22 commitments.** The outer verifier
  checks no commitment and no proof of knowledge, so such inner circuits are
  rejected outright.
- **Your verifying key varies at runtime.** The inner key is baked in as a
  compile-time constant.
- **You are shipping to mainnet without an audit.** This is unaudited
  cryptographic code. See [SECURITY.md](SECURITY.md).

## What it costs

Every gain below is bought with on-chain gas. polyring's ring checks draw
three BSB22 commitments instead of gnark's one, and the on-chain verifier has
to check each of them, so the contract grows and `verifyProof` burns more gas.
That is the whole trade: a cheaper prover for a more expensive verifier.

Measured on a simulated EVM over a real inner proof, outer verifier on BN254
(`go test ./examples/recursion/ -run TestOuterOnChain -v`):

| Metric | gnark | polyring | Delta |
| :--- | ---: | ---: | ---: |
| R1CS constraints | 791,400 | 491,043 | **−38.0%** |
| BSB22 commitments | 1 | 3 | +2 |
| Proof size | 384 B | 512 B | +128 B |
| Contract size | 7,407 B | 10,394 B | +2,987 B |
| `verifyProof` gas | 358,571 | 459,994 | **+101,423 (+28.3%)** |

So: 38% off the prover, 28% onto the verifier. Whether that is a win depends
on how often you prove against how often you verify — a prover that proves
once and a verifier that verifies many times is the case polyring loses.

## Benchmark

The outer verifier circuit (`std/recursion`) over a genuine MiMC inner proof,
with gnark's pairing vs polyring's ring pairing. Same circuit, same statement;
only the pairing check differs. Outer field is BN254 in every case.

"gnark's pairing" here is gnark's own in-circuit pairing —
`sw_bn254.Pairing.PairingCheck` / `sw_bls12381.PairingCheck` — which runs a
full Miller loop over 𝔽p¹² per pair.

| Inner curve | Metric | gnark | polyring | Delta |
| :--- | :--- | ---: | ---: | ---: |
| **BN254** | R1CS constraints | 791,400 | 491,043 | −38.0% |
| | Committed variables | 589,535 | 398,959 | −32.3% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 320 ms | 189 ms | −41.0% |
| | Compile time¹ | 1,750 ms | 1,040 ms | −40.6% |
| **BLS12-381** | R1CS constraints | 979,700 | 677,317 | −30.9% |
| | Committed variables | 731,178 | 539,891 | −26.2% |
| | BSB22 commitments | 1 | 3 | 2 extra verifier pairings |
| | Witness solve time¹ | 364 ms | 232 ms | −36.3% |
| | Compile time¹ | 2,230 ms | 1,527 ms | −31.5% |

```
R1CS constraints (lower is better)
BN254      gnark    [███████████████░░░░░]   791,400
           polyring [█████████░░░░░░░░░░░]   491,043  (-38.0%)
BLS12-381  gnark    [████████████████████]   979,700
           polyring [███████████████░░░░░░]   677,317  (-30.9%)
```

¹ Solve and compile times are indicative: they jitter by 20% or more run to run,
and the delta moves with them. The constraint counts are exact and reproduce
to the digit. Hardware: Apple M3 Pro 36gb, 20 iterations, median of 3 runs.

### Groth16 phases

R1CS constraints per verifier phase. kSum, the G1 checks and the Bs ladder
(on-twist and subgroup check included: Bs needs no separate `AssertIsOnG2`)
are measured from small isolating circuits; loop+tail+previous (Miller
accumulation, final exponentiation/residue tail, folded-in e(α,β)) is the
remainder, so phases sum to the total. Delta is gnark − polyring. The ladder
row is a marginal (witness `Bs` minus the same check with precomputed lines),
so it also picks up batching effects from the rest of the circuit; in an
isolating ladder circuit, polyring's ladder is 1,348 constraints below
gnark's.

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

Re-run locally for your numbers (`lib/profile`, plus the bare two-pair check in
`std/ringpairing`):
`go test ./... -run=^$ -bench=. -benchtime=1x -v`.

## Quickstart

```sh
go get github.com/mistcash/polyring
go test ./examples/recursion/ -run TestGroth16Verifier -v
```

polyring needs a builder fix from gnark that is not upstream yet, so your own
`go.mod` needs the same `replace` polyring has — Go ignores a dependency's
`replace` directives:

```
require github.com/mistcash/polyring v0.0.0-...

replace github.com/consensys/gnark v0.16.4 => github.com/mistcash/tiny-gnark v0.0.0-20261018205550-0a3abd2ee477
```

Check `go.mod` for the pinned pseudo-version; it moves. Without the
`replace`, upstream gnark compiles the circuit but the emulated field fails
its own deferred multiplication check and the outer circuit rejects a
*genuine* proof. It fails loudly rather than silently, but it does not work.

Template: `examples/recursion` (inner: `examples/mimc`, MiMC preimage, on
either curve). Copy it.

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

Two things bite people embedding this in a larger circuit:

- **The inner verifying key is a compile-time constant.** The same `vk` has to
  go into the circuit you compile and the assignment you witness.
- **The ring checker has to be registered before anything else creates an
  emulated field.** The ring checks emit range checks of their own, and gnark
  runs deferred callbacks in registration order, so the first emulated field
  in your circuit has to be the ring's. `recursion.NewVerifier` does this for
  you — call it before anything else in `Define`. If you build the verifier
  yourself with `NewVerifierWithPairing`, the same rule applies.

On-chain verifier (required — gnark's generator supports 1 commitment, ring
circuits draw 3):

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

`lib/solidity` demonstrates the multi-commitment generator on a small
circuit; the full flow over the real outer circuit — prove, generate, deploy,
verify, reject tampered commitments — is
`examples/recursion/onchain_test.go`.

## Further work

- **Infinite recursion:** write the outer verifier to handle inner BSB22
  commitments (including their PoK checks), so an outer proof can itself be
  recursed. Open question under investigation: whether the ~38% prover saving
  per level still outweighs the extra verifier pairings as depth grows.
- **Variable VK:** allow variable circuit verification.
- **Aggregation:** verify multiple inner proofs in one outer (shared Miller
  loop / batched check) for larger savings. Not yet implemented.

## Requirements

- Go 1.26.8
- `solc` on `PATH` only for the on-chain tests (skipped without it)

No other setup. The `replace` in `go.mod` is the one thing a consuming module
has to repeat — see [Quickstart](#quickstart).

## How it works

Pairing over the polynomial ring `F_p[w]/(w^12 − 2ξ₀w^6 + ξ₀² + 1)` — `x^12 −
18x^6 + 82` for BN254, `x^12 − 2x^6 + 2` for BLS12-381 — with deferred
product checks (one batched Schwartz–Zippel identity), following [On Proving
Pairings](https://eprint.iacr.org/2024/640.pdf). Only `e(A,B)` runs the full
Miller loop; `e(α,β)` is folded in as a constant previous value and
`e(L,γ)`, `e(C,δ)` use precomputed lines. The Miller loop driver and residue
check are shared (`std/ringpairing`); each curve package owns its twist — G2
ladder, line shape, subgroup check, loop schedule — on gnark's own 𝔽p²
arithmetic (`std/ring_bn254`, `std/ring_bls12381`). Details there and in
`std/polyring`.

The deferred checks are what cost the extra BSB22 commitments: each ring
product check commits to a remainder and a quotient, and gnark's range
checker commits once more.

## Layout

| path | what |
| --- | --- |
| `std/recursion` | outer Groth16 verifier, generic over the inner curve — start here |
| `std/ringpairing` | ring pairing core: ring, Miller loop driver, `PairingCheck`, the `Curve` interface |
| `std/ring_bn254`, `std/ring_bls12381` | per-curve ring pairing: twist, G2 ladder, hints, `NewPairing` |
| `std/polyring` | deferred product checker |
| `lib/solidity` | multi-commitment verifier exporter |
| `lib/gnarkpairing` | the same outer circuit over gnark's pairing — the baseline |
| `lib/soltest` | deploys a generated verifier to a simulated EVM |
| `lib/limbcomposition` | limb recomposition, vendored from gnark |
| `examples/mimc`, `examples/recursion` | inner statement + end-to-end flow, on chain included |
| `lib/profile`, `lib/bench` | Groth16 bench (both curves, gnark vs polyring) + compile-and-solve helper |

## Tests

```sh
go test ./...                                  # everything, on-chain tests included
go test -short ./...                           # skip the on-chain tests
./lib/profile/pprof-groth16.sh                 # profiles + full bench sweep → bench/groth16-delta.txt, needs graphviz `dot`
```

## Security

Unaudited. Please read [SECURITY.md](SECURITY.md) before reporting anything,
and before using this on anything you care about.

## License

Apache-2.0, see [LICENSE](LICENSE). Please cite this work — see
[CITATION.cff](CITATION.cff).
