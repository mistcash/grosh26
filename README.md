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

## Layout

| path | what it is |
| --- | --- |
| `field_polyring.go` | the ring checker: deferred product checks over `𝔽p[x]/(mod)`, batched with a Schwartz-Zippel argument |
| `std/ring_bn254` | the ring bolted onto gnark's `fields_bn254.Ext12`, and the Miller loop and pairing check built on it |
| `circuits/pairing` | the demonstration circuit: `e(P1,Q1)·e(P2,Q2) == 1` with the G1 points public |
| `cmd/grosh26` | compile, set up, prove, verify, and export the verifier contract |
| `solidity` | the Solidity generator, for circuits with more than one commitment |

## Running it

```sh
go run ./cmd/grosh26 setup      # circuit.r1cs, circuit.pk, circuit.vk, Verifier.sol
go run ./cmd/grosh26 prove      # proof.bin, public.wtns, calldata.json
go run ./cmd/grosh26 verify     # off-chain check
go run ./cmd/grosh26 solidity   # regenerate Verifier.sol from circuit.vk
```

Artifacts land in `build/` (`-dir` to change it). `calldata.json` holds the
packed proof and the 16 public inputs `verifyProof` takes.

The circuit is 654,327 constraints; gnark's own `PairingCheck` over the same
statement is 736,686, so the ring saves about 11%. Setup takes a couple of
minutes and a proof under ten seconds.

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
go test ./...        # includes a 654k-constraint setup, a couple of minutes
go test -short ./... # skips it
```

The on-chain tests compile the exported verifier with `solc` and run it against
go-ethereum's simulated backend. They skip when `solc` is not on `PATH`; set
`SOLC_BIN` to point at one.

The 𝔽p¹² ring operations and the Miller loop follow
[tiny-gnark's `ppp` branch](https://github.com/mistcash/tiny-gnark/tree/ppp/std/algebra/emulated),
reduced to the parts that actually differ from gnark.
