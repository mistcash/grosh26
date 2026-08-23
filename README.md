# grosh26

Polynomial ring emulation for gnark circuits, and a BN254 𝔽p¹² circuit built on
it that verifies on chain.

Emulating a big field inside a small one is expensive because every product has
to be reduced. The polynomial ring checker takes the other route: the prover
hands back the product and the quotient of the Euclidean division through a
hint, and every such claim in a circuit is batched into one identity checked at
a single random point after `Define` returns.

## Layout

| path | what it is |
| --- | --- |
| `field_polyring.go` | the polynomial ring checker: deferred product checks over `𝔽p[x]/(mod)`, batched with a Schwartz-Zippel argument |
| `std/fields_bn254` | 𝔽p¹² as the direct extension `𝔽p[x]/(x¹² - 18x⁶ + 82)`, with multiplication, squaring, inversion, division and the Frobenius maps |
| `circuits/fq12` | the demonstration circuit: prove knowledge of a secret `X ∈ 𝔽p¹²` whose 65537-th power is a public `Y` |
| `cmd/fq12` | the binary that compiles the circuit, runs the setup, proves, verifies and exports the Solidity verifier |
| `backend/groth16/bn254` | gnark's BN254 Groth16 backend, vendored, with the multi-commitment fixes the generated verifier needs |

## Running it

```sh
go run ./cmd/fq12 setup                # circuit.r1cs, circuit.pk, circuit.vk, Verifier.sol
go run ./cmd/fq12 prove -seed hello    # proof.bin, public.wtns, calldata.json
go run ./cmd/fq12 verify               # off-chain check
go run ./cmd/fq12 solidity             # regenerate Verifier.sol from circuit.vk
```

Artifacts land in `build/` by default (`-dir` to change it). `calldata.json`
holds the packed proof and the 48 public inputs that `verifyProof` takes.

The circuit is 27k constraints with 48 public inputs, so the setup takes a few
seconds and a proof under a second on a laptop.

## Provers and the generated verifier

The setup is gnark's. The proof is produced by gnark's Groth16 prover, but by
the copy vendored in `backend/groth16/bn254` rather than the one in
`github.com/consensys/gnark`, and that matters here.

The circuit draws three commitments: two for the polynomial ring checks and one
for the range checker. Upstream folds the commitments' proofs of knowledge with
a challenge from `fr.Hash` (RFC 9380 `expand_message_xmd`), which a Solidity
verifier has no affordable way to recompute; the vendored prover routes that
challenge through the same keccak hasher as everything else the contract has to
reproduce. A proof from the upstream prover is perfectly valid off chain and is
rejected by the contract. `fq12 prove -upstream` produces one, and
`TestSolidityVerifier` pins both outcomes.

The 𝔽p¹² arithmetic follows
[tiny-gnark's `ppp` branch](https://github.com/mistcash/tiny-gnark/blob/ppp/std/algebra/emulated/fields_bn254/e12.go),
adapted to the standalone checker in this repository.

## Tests

```sh
go test ./...
```

The on-chain test compiles the exported verifier with `solc` and runs it against
go-ethereum's simulated backend. It skips when `solc` is not on `PATH`; set
`SOLC_BIN` to point at one.
