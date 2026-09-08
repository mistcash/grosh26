# grosh26

grosh26 is a Go library for [gnark](https://github.com/Consensys/gnark) that
makes two things cheaper when you're building zk-SNARK circuits on BN254:
verifying a Groth16 pairing *inside* another circuit, and verifying a Groth16
proof with more than one commitment *on-chain*. Together they let you build a
circuit that checks another circuit's proof — a proof of a proof — and deploy
a Solidity verifier for it.

Concretely, it ships two pieces:

- **A cheaper in-circuit BN254 pairing check.** Verifying a Groth16 proof
  inside a circuit means doing a pairing check in-circuit, and pairings are
  where most of the constraint budget goes. grosh26's pairing checks the
  𝔽p¹² arithmetic in 𝔽p[x]/(x¹² - 18x⁶ + 82) instead of gnark's product-by-product
  reduction.
- **A multi-commitment Solidity verifier generator.** gnark's own generator
  can only emit a verifier contract for a proof with at most one BSB22
  commitment. grosh26's circuits use three (that's what the cheaper pairing
  check costs in commitments), so this repo ships a generator that handles
  proofs with more than one.

**This version is unaudited.** It has not had an external cryptographic review.
One soundness question is known and open — see [Review](#review) below —
and there may be others no one has looked for yet. Do not use this in
anything that handles real value without an audit first.

## Layout

| path | what it is |
| --- | --- |
| `std/polyring` | the ring checker: deferred product checks over `𝔽p[x]/(mod)`, batched with a Schwartz-Zippel argument |
| `std/ring_bn254` | the ring bolted onto gnark's `fields_bn254.Ext12`, and the Miller loop and pairing check built on it |
| `std/recursion` | the outer Verifier circuit: a Groth16 proof of an inner circuit, checked via the ring pairing |
| `solidity` | the Solidity generator, for circuits with more than one commitment |
| `examples/poseidon` | an inner circuit to recurse over: a poseidon 2→1 compression preimage |
| `examples/recursion` | the end-to-end example: a Groth16 proof of the poseidon circuit verified by the outer circuit |

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

## Recursion: a Groth16 proof inside a Groth16 proof

`std/recursion` is a Groth16 verifier built as a circuit, so one Groth16 proof
can attest that another Groth16 proof verifies. The inner statement
(`examples/poseidon`) is deliberately small — knowledge of a preimage `(a, b)`
to a Poseidon2 2-to-1 compression digest — so that the interesting cost is
entirely in the outer circuit, not the inner one. `examples/recursion` runs
the whole flow and is the template to copy: swap in your own inner circuit's
verifying key and public inputs to recurse over a different statement.

The outer `Verifier` circuit takes the inner circuit's verifying key as a
compile-time constant (baked in via `NewVerifyingKey`, not a witness), and its
`Define` reproduces the Groth16 pairing identity

```
e(A, B) · e(α, β)⁻¹ · e(L, γ)⁻¹ · e(C, δ)⁻¹ = 1
```

as a single four-term `PairingCheck` through
[`ring_bn254`](std/ring_bn254). Only one of the four terms is a full pairing.
β, γ and δ come from the verifying key and never vary, so three of the four
in-circuit `[6x₀+2]Q` ladders are avoidable:

| term | what varies | cost in the circuit |
| --- | --- | --- |
| `e(A, B)` | both points | a full pairing: B's ladder and G2 subgroup check run in-circuit |
| `e(α, β)⁻¹`, `e(L, γ)⁻¹`, `e(C, δ)⁻¹` | G1 only | fixed-Q pairs: the G2 lines are precomputed off-circuit |

Three fixed-Q pairs and one full pairing, then, over a single Miller loop —
which takes the outer circuit from 1,269,953 constraints to **660,886**, a
48.0% cut, for the same statement. Skipping a ladder skips the G2 subgroup
check with it, so `NewFixedG2` runs that check off-circuit instead and
refuses to bake in a point off the twist, outside the prime-order subgroup,
or at infinity.

The outer circuit carries three BSB22 commitments — two from the ring's
deferred checks, one from the range checker — verified on-chain by the
generator in `solidity/`.

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

To verify the outer proof on-chain, export the verifier with `solidity`
instead of gnark's generator — it is the only part of the proving stack this
repo replaces:

```go
// outerVK is the *outer* circuit's native Groth16 verifying key.
f, _ := os.Create("Verifier.sol")
defer f.Close()
solidity.ExportSolidity(outerVK.(*groth16bn254.VerifyingKey), f)
```

The prover is not replaced: gnark's setup, prover and off-chain verifier are
used unmodified — they handle multiple commitments fine. Only the contract
generator is new: this circuit draws three commitments, and gnark's template
neither sums more than two commitment points correctly nor derives the
challenge that folds their proofs of knowledge. The folding challenge is what
gnark's prover computes with `fr.Hash`, i.e. RFC 9380 `hash_to_field` with
`expand_message_xmd` over SHA-256 and the domain separation tag `G16-BSB22`;
the contract reproduces it in `sha256` precompile calls. That is what lets the
stock prover and this verifier agree.

## Tests

```sh
go test ./...        # full suite, including the outer circuit (~640k constraints)
go test -short ./... # skips nothing at the moment; every remaining test is cheap
```

The on-chain test in `solidity/` compiles the exported verifier with `solc`
and runs it against go-ethereum's simulated backend. It skips when `solc` is
not on `PATH`; set `SOLC_BIN` to point at one.

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
