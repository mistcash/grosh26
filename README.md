# grosh26

grosh26 is a Go library for [gnark](https://github.com/Consensys/gnark) that
makes two things cheaper when you're building zk-SNARK circuits on BN254:
verifying a Groth16 pairing *inside* another circuit, and verifying a Groth16
proof with more than one commitment *on-chain*. Together they let you build a
circuit that checks another circuit's proof — a proof of a proof — and deploy
a Solidity verifier for it, which is the machinery a lot of real recursive-SNARK
and zk-rollup style systems are built out of.

Concretely, it ships two pieces:

- **A cheaper in-circuit BN254 pairing check.** Verifying a Groth16 proof
  inside a circuit means doing a pairing check in-circuit, and pairings are
  where most of the constraint budget goes. grosh26's pairing checks the
  𝔽p¹² arithmetic in 𝔽p[x]/(x¹² - 18x⁶ + 82) instead of gnark's product-by-product
  reduction — about 10% fewer constraints for the same statement.
- **A multi-commitment Solidity verifier generator.** gnark's own generator
  can only emit a verifier contract for a proof with at most one BSB22
  commitment. grosh26's circuits use three (that's what the cheaper pairing
  check above costs in commitments), so this repo ships a generator that
  handles proofs with more than one — the actual novel piece needed to get
  a "proof of a proof" verified on a generic EVM.

**v0.1.0 is unaudited.** It has not had an external cryptographic review.
One soundness question is known and open — see [Review](#review) below —
and there may be others no one has looked for yet. Do not use this in
anything that handles real value without an audit first.

## Example use cases

- **Recursive proof verification / proof aggregation.** Verify a Groth16
  proof of some inner statement inside an outer circuit, so the outer proof
  attests "this inner proof is valid" without re-running the inner
  computation. `std/recursion` is exactly this, demonstrated end to end —
  see [Recursion](#recursion-a-groth16-proof-inside-a-groth16-proof) below.
- **Off-chain computation, on-chain trust.** Run an expensive computation off
  chain (in the inner circuit), prove it, wrap that proof in an outer
  recursive proof, and verify only the outer proof on-chain — the contract
  never sees or re-executes the inner computation, just trusts the recursive
  proof of it.
- **Cutting gas on any Groth16 verifier that needs multiple BSB22
  commitments.** Even without recursion: any gnark circuit that ends up with
  more than one commitment (large circuits with multiple `Commit` calls, or
  circuits composed from several sub-gadgets that each commit) can't get a
  verifier contract from gnark's own generator. `solidity/` alone — independent
  of the ring pairing — solves that.
- **A worked template to build your own recursive circuit from.** `std/recursion`'s
  `Circuit` is a reusable outer circuit parameterized by an inner verifying
  key; `circuits/poseidon` is the shipped example of an inner circuit. Swap in
  your own inner circuit's verifying key and public inputs to recurse over a
  different statement:

  ```go
  // vk is the inner circuit's native Groth16 verifying key.
  vk, err := recursion.NewVerifyingKey(innerVK)

  // Same vk for both the unassigned circuit (compile) and the witness (prove).
  outerCcs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, recursion.NewCircuit(vk))
  outerPK, outerVK, _ := groth16.Setup(outerCcs)

  assignment := recursion.NewCircuit(vk)
  assignment.Proof, _ = recursion.ValueOfProof(innerProof)
  assignment.PublicWitness = recursion.ValueOfPublicWitness(innerPublicInputs)
  witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
  outerProof, _ := groth16.Prove(outerCcs, outerPK, witness)
  ```

  See `cmd/grosh26/recursive.go` for the full, error-checked version of this
  flow (it's what the CLI runs).

Emulating a big field inside a small one is expensive because every product has
to be reduced. The ring takes the other route: the prover claims a product and
its quotient through a hint, and every claim in a circuit is batched into one
identity checked at a single random point after `Define` returns.

Everything that is not the ring comes from gnark. The 𝔽p¹² element type and its
coefficient-wise operations, the Frobenius maps, the tower conversions, the G1
and G2 point types, the subgroup checks, the residue witness hint, the setup,
the prover and the off-chain verifier are all gnark's, used as they are.

gnark comes from [tiny-gnark's `pre-merge` branch](https://github.com/mistcash/tiny-gnark/tree/pre-merge),
a fork that keeps the upstream module path, so it is wired in with a single
`replace` directive and every import still reads `github.com/consensys/gnark`.
The fork is v0.16.0 plus fixes on their way upstream; the one this repository
needs is in `frontend/cs/r1cs`, where `builder.Commit` looked an
already-committed wire's commitment up in a list it had partly consumed. Two
commitments were enough to make it pick the wrong one or run off the end, and
the ring draws two before the range checker draws its own, so on stock gnark
these circuits do not compile at all.

## Layout

| path | what it is |
| --- | --- |
| `field_polyring.go` | the ring checker: deferred product checks over `𝔽p[x]/(mod)`, batched with a Schwartz-Zippel argument |
| `std/ring_bn254` | the ring bolted onto gnark's `fields_bn254.Ext12`, and the Miller loop and pairing check built on it |
| `circuits/pairing` | the demonstration circuit: `e(P1,Q1)·e(P2,Q2) == 1` with the G1 points public |
| `circuits/poseidon` | the inner circuit for the recursion demo: a poseidon 2→1 compression preimage |
| `std/recursion` | the outer Verifier circuit: a Groth16 proof of the inner circuit, checked via the ring pairing |
| `cmd/grosh26` | drives the recursive flow: set up both circuits, prove inner then outer, verify, export the verifier contract |
| `solidity` | the Solidity generator, for circuits with more than one commitment |

## Running it

```sh
go run ./cmd/grosh26 setup      # inner.{r1cs,pk,vk}, outer.{r1cs,pk,vk}, Verifier.sol
go run ./cmd/grosh26 prove      # outer.proof, outer.public.wtns, calldata.json
go run ./cmd/grosh26 verify     # off-chain check of the outer proof
go run ./cmd/grosh26 solidity   # regenerate Verifier.sol from outer.vk
```

Artifacts land in `build/` (`-dir` to change it). `calldata.json` holds the
packed proof and the 16 public inputs `verifyProof` takes.

The circuit is 659,592 constraints; gnark's own `PairingCheck` over the same
statement is 736,686, so the ring saves about 10%. Setup takes under a minute
and a proof a couple of seconds.

## Recursion: a Groth16 proof inside a Groth16 proof

`std/recursion` is a second, self-contained demonstration: a Groth16 verifier
built as a circuit, so one Groth16 proof can attest that another Groth16 proof
verifies. The inner statement (`circuits/poseidon`) is deliberately small —
knowledge of a preimage `(a, b)` to a Poseidon2 2-to-1 compression digest — so
that the interesting cost is entirely in the outer circuit, not the inner one.

The outer `Verifier` circuit takes the inner circuit's verifying key as a
compile-time constant (baked in via `NewVerifyingKey`, not a witness), and its
`Define` reproduces the Groth16 pairing identity

```
e(A, B) · e(α, β)⁻¹ · e(L, γ)⁻¹ · e(C, δ)⁻¹ = 1
```

as a single four-term `PairingCheckPairs` through
[`ring_bn254`](std/ring_bn254), the same ring pairing the standalone demo
above uses. `cmd/grosh26`'s `setup` and `prove` commands drive the whole thing
end to end: compile and set up the inner circuit, prove a random preimage,
verify it, then compile and set up the outer circuit around that verifying
key, and prove *that* the inner proof verifies.

Only one of the four terms is a full pairing. β, γ and δ come from the
verifying key and never vary, so three of the four in-circuit `[6x₀+2]Q`
ladders are avoidable:

| term | what varies | cost in the circuit |
| --- | --- | --- |
| `e(A, B)` | both points | a full pairing: B's ladder and G2 subgroup check run in-circuit |
| `e(L, γ)⁻¹`, `e(C, δ)⁻¹` | G1 only | fixed-Q pairs: γ's and δ's lines are precomputed off-circuit |
| `e(α, β)⁻¹` | nothing | a constant: its Miller loop value is folded in as one factor |

Two fixed-Q pairs and one full pairing, then, over a single Miller loop —
which takes the outer circuit from 1,269,953 constraints to **640,138**, a
49.6% cut, for the same statement. Skipping a ladder skips the G2 subgroup
check with it, so `NewFixedQPair` and `NewFixedPair` run that check
off-circuit instead and refuse to bake in a point off the twist, outside the
prime-order subgroup, or at infinity.

The outer circuit carries three BSB22 commitments — two from the ring's
deferred checks, one from the range checker — the same shape the standalone
pairing demo has, verified on-chain by the same generator. It takes a few
seconds to prove and about a minute and a half to set up.

## Gas

Measured against go-ethereum's simulated backend, `solc --optimize`, no
further tuning:

| circuit | constraints | commitments | deploy (bytecode / gas) | `verifyProof` gas |
| --- | --- | --- | --- | --- |
| `circuits/pairing` (standalone ring pairing) | 659,592 | 3 | 12,931 bytes / 2,843,413 | 542,975 |
| `std/recursion` (Groth16-in-Groth16) | 640,138 | 3 | 10,414 bytes / 2,298,785 | 461,338 |

The recursive proof is cheaper to verify on-chain than the standalone pairing
demo, and the two circuits behind them are now within 3% of each other in
size — an entire Groth16 verifier for about what one bare pairing check
costs. On-chain, size does not enter into it: both proofs are 512 bytes and
the same shape (Groth16 with three commitments), so `verifyProof`'s gas is a
function of the public input count (16 vs. 4), not of what was proved.

## Why the Solidity generator is ours

The prover is not. gnark's setup, prover and verifier are used unmodified — they
handle multiple commitments fine. Its *generator* does not: this circuit draws
three commitments (two for the ring checks, one for the range checker), and
gnark's template neither sums more than two commitment points correctly nor
derives the challenge that folds their proofs of knowledge.

The generator here does both. The folding challenge is what gnark's prover
computes with `fr.Hash`, i.e. RFC 9380 `hash_to_field` with `expand_message_xmd`
over SHA-256 and the domain separation tag `G16-BSB22`; the contract reproduces
it in three `sha256` precompile calls. That is what lets the stock prover and
this verifier agree.

## Tests

```sh
go test ./...        # includes full circuit setups (up to 1.3M constraints), several minutes
go test -short ./... # skips them
```

The on-chain tests compile the exported verifier with `solc` and run it against
go-ethereum's simulated backend. They skip when `solc` is not on `PATH`; set
`SOLC_BIN` to point at one.

The 𝔽p¹² ring operations and the Miller loop follow
[tiny-gnark's `ppp` branch](https://github.com/mistcash/tiny-gnark/tree/ppp/std/algebra/emulated),
reduced to the parts that actually differ from gnark.

## Review

External cryptographers reviewing the novel surface (the deferred ring
check, the ring pairing, the recursion, the multi-commitment verifier)
should start at [`docs/review-spec.md`](docs/review-spec.md): the soundness
arguments, and the deliberate deviations and open items, stated explicitly.

## License

Apache-2.0, see [LICENSE](LICENSE). See [CHANGELOG](CHANGELOG.md) for release
notes.
