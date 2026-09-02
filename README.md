# grosh26

Polynomial ring emulation for gnark circuits: a BN254 pairing whose 𝔽p¹²
arithmetic is checked in 𝔽p[x]/(x¹² - 18x⁶ + 82) instead of being reduced
product by product, and the Solidity verifier that goes with it.

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

as a single four-term `PairingCheck` through [`ring_bn254`](std/ring_bn254),
the same ring pairing the standalone demo above uses. `cmd/grosh26`'s `setup`
and `prove` commands drive the whole thing end to end: compile and set up the
inner circuit, prove a random preimage, verify it, then compile and set up the
outer circuit around that verifying key, and prove *that* the inner proof
verifies.

The outer circuit compiles to 1,269,392 constraints (a few seconds to prove,
under a minute and a half to set up) and carries three BSB22 commitments —
two from the ring's deferred checks, one from the range checker — the same
shape the standalone pairing demo has, verified on-chain by the same
generator.

## Gas

Measured against go-ethereum's simulated backend, `solc --optimize`, no
further tuning:

| circuit | constraints | commitments | deploy (bytecode / gas) | `verifyProof` gas |
| --- | --- | --- | --- | --- |
| `circuits/pairing` (standalone ring pairing) | 659,592 | 3 | 12,931 bytes / 2,843,413 | 542,975 |
| `std/recursion` (Groth16-in-Groth16) | 1,269,392 | 3 | 10,395 bytes / 2,294,920 | 459,994 |

The recursive proof is cheaper to verify on-chain than the standalone pairing
demo despite the much larger circuit behind it — both proofs are 512 bytes and
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

## License

Apache-2.0, see [LICENSE](LICENSE). See [CHANGELOG](CHANGELOG.md) for release
notes.
