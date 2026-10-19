# Security Policy

**polyring is unaudited research software.** It implements a pairing check
inside a SNARK circuit — the kind of code where a subtle bug is a soundness
break, not a crash. Treat it as such: do not use it to secure funds, and do
not put it in front of untrusted provers without an audit of your own.

## Supported versions

There are no releases yet. Everything on `main` is pre-1.0 and the API is
expected to change.

| Version | Supported |
| :--- | :--- |
| `main` | yes, best effort |
| anything else | no |

## Reporting a vulnerability

Report it privately through GitHub's security advisory form:

<https://github.com/mistcash/polyring/security/advisories/new>

If private advisory reporting is unavailable to you, open a regular issue
marked with the `security` label and say plainly that you are reporting a
vulnerability — do not include a working exploit in a public issue.

Please include: the curve and the circuit you were running, the commit you
ran, and the smallest reproduction you have.

### What is in scope

- A break of the Groth16 pairing identity the outer circuit checks: a proof
  that the circuit accepts but gnark rejects, or the reverse.
- A break of the deferred ring checks in `std/polyring`: a hint that lets a
  prover satisfy a ring product check without the identity holding.
- A missing or wrong subgroup, on-curve or on-twist check.
- A soundness break in the Solidity verifier in `lib/solidity`: a proof or a
  tampered commitment the contract accepts.
- A range check, limb decomposition or challenge truncation that leaves a
  malleable value.

### What is out of scope

- Gas costs and contract size.
- The fact that the code is unaudited, or that it has no formal
  verification.
- Denial of service through a deliberately expensive circuit — that is the
  caller's budget, not a vulnerability.
- Attacks on gnark or gnark-crypto themselves: report those upstream.

## Response

Acknowledgement within a week, triage within two. Fixes land on `main` as
soon as they are ready; there is no release train to wait for.
