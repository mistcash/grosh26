# Getting started

polyring verifies a Groth16 proof inside another Groth16 proof. This page gets
you from nothing to a verified recursive proof, then to one that verifies
on-chain.

## Install

```sh
go get github.com/mistcash/polyring
```

polyring needs a builder fix from gnark that is not upstream yet, so it pins
[`mistcash/tiny-gnark`](https://github.com/mistcash/tiny-gnark), a pre-merge
branch of gnark.

**Your `go.mod` needs the same `replace` polyring has**, because Go ignores a
dependency's `replace` directives:

```
require github.com/mistcash/polyring v0.0.0-...

replace github.com/consensys/gnark v0.16.4 => github.com/mistcash/tiny-gnark v0.0.0-20261018205550-0a3abd2ee477
```

Check polyring's `go.mod` for the pinned pseudo-version; it moves.

Without the `replace`, upstream gnark compiles the circuit but the emulated
field fails its own deferred multiplication check, and the outer circuit
rejects a *genuine* proof:

```
[assertIsEqual] 8266821137240084212832221726948255298930443109697265459924253391335382591804 == 9164574245616912452706406325580817612515590503736229678796100192067035742639
    emulated.(*mulCheck[...]).check
```

It fails loudly rather than silently, but it does not work. If you see that
error, the `replace` is missing or points at a different version.

Requirements:

- Go 1.26.8 or later
- `solc` on `PATH`, only for the on-chain tests (they skip without it)

## Run the example

```sh
go test ./examples/recursion/ -run TestGroth16Verifier -v
```

That is the whole demo: a Groth16 proof of a MiMC preimage
(`examples/mimc`) over BN254 or BLS12-381, verified inside a BN254 outer
circuit by `std/recursion`. The test also checks that tampered proofs, a
malformed verifying key and a wrong public input are all rejected.

To see the on-chain flow, which proves the outer circuit for real, generates
its Solidity verifier and runs it against a simulated EVM:

```sh
go test ./examples/recursion/ -run TestOuterOnChain -v
```

It prints the cost table the readme quotes.

## Write your own

The shape of the flow is: compile the inner circuit, prove it, bake its
verifying key into the outer circuit, prove that, and verify the outer proof.

```go
import (
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "github.com/mistcash/polyring/std/recursion"
)

// 1. the inner circuit's key, proof and public witness
innerVK, innerProof, innerPublic := ...

// 2. the inner key, prepared for use as the outer circuit's constants
vk, err := recursion.NewVerifyingKey(innerVK)
if err != nil {
    return err
}

// 3. the outer circuit: compile and assign it
outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
    recursion.NewBN254Circuit(vk))
if err != nil {
    return err
}

assignment := recursion.NewBN254Circuit(vk)
if err := assignment.Assign(innerProof, innerPublic); err != nil {
    return err
}
witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
if err != nil {
    return err
}

// 4. setup, prove and verify the outer circuit -- stock gnark from here
pk, outerVK, err := groth16.Setup(outerCcs)
if err != nil {
    return err
}
outerProof, err := groth16.Prove(outerCcs, pk, witness)
if err != nil {
    return err
}
outerPublic, err := witness.Public()
if err != nil {
    return err
}
if err := groth16.Verify(outerProof, outerVK, outerPublic); err != nil {
    return err
}
```

For a BLS12-381 inner proof, use `recursion.NewBLS12381Circuit` instead. The
outer circuit is over BN254 either way.

## Two things that bite

### The inner verifying key is a compile-time constant

`recursion.NewVerifyingKey` takes a native gnark verifying key and bakes its
points into the outer circuit as constants. That means the same `vk` has to
go into the circuit you compile and the assignment you witness:

```go
outerCcs, _ := frontend.Compile(..., recursion.NewBN254Circuit(vk))
assignment := recursion.NewBN254Circuit(vk)   // the same vk
```

This is also why there is no variable-key verification: the key is part of
the circuit, not the witness.

### The ring checker registers first

The deferred ring checks emit range checks of their own, and gnark runs
deferred callbacks in registration order. The first emulated field in your
circuit has to be the ring's.

`recursion.NewVerifier` handles this for you — call it before anything else
in `Define`. If you build the verifier yourself with
`recursion.NewVerifierWithPairing`, the same rule applies: create the pairing
first, then the verifier, then anything else.

## On-chain

The outer proof carries three BSB22 commitments, which gnark's Solidity
generator does not support — it handles one. Use polyring's generator:

```go
import (
    "github.com/consensys/gnark/backend"
    "github.com/consensys/gnark/backend/groth16"
    gnarksolidity "github.com/consensys/gnark/backend/solidity"
    "github.com/mistcash/polyring/lib/solidity"
)

proof, err := groth16.Prove(outerCcs, pk, witness,
    gnarksolidity.WithProverTargetSolidityVerifier(backend.GROTH16))
if err != nil {
    return err
}

var out bytes.Buffer
if err := solidity.ExportSolidity(outerVK.(*groth16bn254.VerifyingKey), &out); err != nil {
    return err
}
calldata := solidity.MarshalSolidity(proof.(*groth16bn254.Proof))
```

`ExportSolidity` writes a contract with `verifyProof(bytes,uint256[])`, and
`MarshalSolidity` packs the proof the way that contract expects: the Groth16
points, then the commitment points, then the proof of knowledge.

The public inputs you pass are the circuit's public inputs *minus* the ones
the commitments are drawn from — the contract recomputes those from the
commitment points and the committed values.

## Limits

- Inner circuits that draw their own BSB22 commitments are rejected.
- One inner proof per outer proof. There is no aggregation yet.
- The outer proof cannot itself be recursively verified yet.
- The code is unaudited. See [SECURITY.md](https://github.com/mistcash/polyring/blob/main/SECURITY.md).
