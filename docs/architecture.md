# Architecture

A map of the packages and the seams between them.

```
std/recursion          the outer Groth16 verifier circuit
  ├── std/ringpairing  the ring pairing core: ring, Miller loop driver,
  │                    PairingCheck, the Curve interface
  │     ├── std/ring_bn254      the BN254 twist, G2 ladder, hints
  │     └── std/ring_bls12381   the BLS12-381 twist, G2 ladder, hints
  └── std/polyring     the deferred product checker over the ring
```

## `std/recursion` — start here

The public entry point. `recursion.Circuit` is a generic outer verifier: it
takes a Groth16 proof of a fixed inner circuit over BN254 or BLS12-381 and
checks it inside a BN254 Groth16 circuit.

- `NewVerifyingKey(vk)` prepares a native gnark verifying key: it checks that
  `α`, `β`, `γ` and `δ` are in their subgroups, negates `γ` and `δ`, and
  computes the constant Miller loop value of `e(α, β)`.
- `NewCircuit(vk)` / `NewBN254Circuit(vk)` / `NewBLS12381Circuit(vk)` build
  the outer circuit.
- `Assign(proof, publicWitness)` fills in the witness.
- `NewVerifier` / `NewVerifierWithPairing` expose the check on its own, for
  embedding in a larger circuit.

The inner key is a compile-time constant, so the same `vk` goes into the
compiled circuit and into the assignment.

## `std/ringpairing` — the shared core

Curve-agnostic. It holds:

- the ring over 𝔽p, and how 𝔽p² elements embed into it;
- the `Curve` interface, which is everything a pairing-friendly curve has to
  provide: the loop counter, the line shape, the twist's ladder, the
  subgroup checks, the 𝔽p¹² maps and gnark's hints;
- `Pairing`, the Miller loop driver and `PairingCheck`;
- the residue check and the accumulator.

It holds nothing about 𝔽p² or G2. That is the point: a new curve is a new
package implementing `Curve`, not a new pairing.

## `std/ring_bn254`, `std/ring_bls12381` — the curve packages

Each one owns its twist and nothing else:

- the G2 ladder, computing the lines for a G2 point given as a witness;
- the line shape, and where the three terms of a line sit on the ring;
- the loop counter, the last lines, and whether the loop's value is
  conjugated;
- the subgroup and on-twist checks;
- gnark's hints, and the 𝔽p¹² tower conversions.

BN254 and BLS12-381 differ in ξ₀, in the loop counter's length, in the
subgroup check's cost and in the conjugation, which is why the split is a
package rather than a flag.

## `std/polyring` — the deferred checker

`PolyRingChecker` registers a deferred callback with gnark's compiler and
holds the product checks until the circuit is defined. It:

- takes polynomial products through `MulPolyRings`, which calls a hint for
  the remainder and the quotient;
- commits to the remainders to draw the challenge `z`;
- batches the quotients outside the circuit with a random linear
  combination, and commits to that to draw the challenge `x`;
- asserts the batched identity at `x`.

The challenge is the commitment's own randomness, used at full width: the
commitment is over the native field, and truncating it would weaken the
Schwartz–Zippel bound.

## `lib/solidity` — the verifier generator

gnark's Solidity generator handles at most one BSB22 commitment: with
several, the contract it emits neither derives the folding challenge nor
sums the commitment points correctly. This package generates a contract that
does.

- `ExportSolidity(vk, w)` writes the contract.
- `MarshalSolidity(proof)` packs a proof the way `verifyProof` expects: the
  Groth16 points, the commitment points, the proof of knowledge.

The contract folds the commitments' proofs of knowledge into a single
pairing check, mirroring gnark-crypto's `pedersen.BatchVerifyMultiVk`: each
commitment is scaled by a successive power of a challenge derived from the
public commitment hashes, and the folded proof of knowledge is checked once
against the shared `G`.

## `lib/gnarkpairing` — the baseline

The same outer circuit, checked with gnark's in-circuit pairing instead of
polyring's. It exists so the two can be compared honestly: same circuit, same
statement, only the pairing check differs. It is also what a user imports to
A/B the two in their own project.

## `lib/soltest` — the simulated EVM

Compiles a generated contract with `solc`, deploys it to a simulated chain
and tears it down with the test. `Deployment.Send` submits a real transaction
so the gas it burns can be read off the receipt.

## `lib/profile`, `lib/bench` — measurement

`lib/bench` compiles a circuit, logs its size and constraint count, and
benchmarks solving it. `lib/profile` runs the outer verifier over both inner
curves and both pairings, breaks the constraints down per verifier phase,
and — with `GNARK_PROFILE_DIR` set — writes gnark's constraint and operation
profiles.

## `lib/limbcomposition` — vendored

A copy of gnark's internal limb composition, moved here because the ring
checker needs it and gnark does not export it.

## `examples/mimc`, `examples/recursion` — the demo

`examples/mimc` is the inner circuit: a MiMC preimage, with parameters
picked from the curve so one circuit serves both inner curves.
`examples/recursion` is the end-to-end flow — proving, verifying, rejecting
tampered proofs, and the on-chain run against a simulated EVM.
