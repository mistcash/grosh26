# polyring

Recursive SNARK tooling: an accelerated BN254 / BLS12-381 pairing check inside gnark circuits, with a multi-commitment Solidity verifier, so that one Groth16 proof can be verified inside another and on-chain.

## Language

**PolyRingChecker**:
The deferred polynomial-ring product checker over 𝔽p[x]/(mod) that replaces repeated extension-field products with hinted products and one batched identity.
_Avoid_: ring checker, polyring emulation

**Deferred ring check**:
Claiming a ring product via a hint during `Define`, then batch-verifying all claims as one Schwartz–Zippel identity at a random point.
_Avoid_: lazy check, batched multiplication

**Ext12 ring**:
gnark's Fp12 direct-extension arithmetic with polynomial-ring operations over the modulus w¹² − 2ξ₀w⁶ + ξ₀² + 1: x¹² − 18x⁶ + 82 for BN254 (ξ₀ = 9), x¹² − 2x⁶ + 2 for BLS12-381 (ξ₀ = 1).

**Ring pairing**:
The BN254 or BLS12-381 pairing computed over the Ext12 ring, following eprint 2024/640. A shared core (`std/ringpairing`) plus one package per curve (`std/ring_bn254`, `std/ring_bls12381`) providing `NewPairing`.
_Avoid_: Fp12 pairing

**Curve package**:
The per-curve half of the ring pairing, implementing `ringpairing.Curve`: the twist and its G2 ladder on gnark's own 𝔽p² arithmetic, the line shape, loop counter, residue tail and gnark's hints. The shared core holds nothing about 𝔽p² or G2.
_Avoid_: curve adapter, curve spec, backend

**Schwartz–Zippel challenge**:
The random ring element at which the deferred identity is evaluated; drawn only after the related operands are committed.
_Avoid_: random point, challenge point

**Fixed-Q pair**:
A Miller loop factor whose G2 point is known when the circuit is built, so its line evaluations are precomputed off-circuit and its ladder and subgroup check never enter the circuit. Built with `sw_bn254.NewG2AffineFixed` / `sw_bls12381.NewG2AffineFixed`.
_Avoid_: precomputed pairing, constant pairing

**Previous Miller loop value**:
A fully-fixed pairing factor passed to the check directly as an 𝔽p¹² element, folded into the Miller product as one factor instead of a pass through the loop. See `ringpairing.Pairing.PairingCheck`, following gnark's `MillerLoopAndMul` pattern. For BLS12-381 it is the conjugated `MillerLoopFixedQ` value, as gnark takes it.
_Avoid_: constant pairing

**BSB22 commitment**:
gnark's batched-Pedersen `Commit`. Polyring proofs carry three: the remainder commitment and the quotient commitment from the deferred ring checks, plus the range checker's own.
_Avoid_: "the 3 commitments" without saying which

**Inner circuit**:
The circuit whose Groth16 proof gets verified inside the outer circuit, over BN254 or BLS12-381. At v0.1: a MiMC preimage proof.
_Avoid_: child circuit, nested circuit

**Outer circuit**:
The Groth16-verifier circuit (`recursion.Circuit`, one generic implementation for both inner curves, always on the BN254 scalar field): inner verifying key baked in as constants, checks an inner proof against the inner public inputs using the ring pairing.
_Avoid_: verifier circuit, wrapper circuit

**Verifier generator**:
The custom Solidity verifier exporter (`lib/solidity/`) that supports proofs with multiple BSB22 commitments, unlike gnark's single-commitment generator.
_Avoid_: gnark's generator (that means the single-commitment one)

**tiny-gnark**:
The pinned gnark fork (pre-merge branch) whose builder fixes this repo's circuits require in order to compile.
_Avoid_: "the fork"
