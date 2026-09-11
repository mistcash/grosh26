# Changelog

## Unreleased

First release as a standalone module. The checker was previously
`std/polyring` inside [grosh26](https://github.com/mistcash/grosh26), which
remains its reference consumer.

- Module path is now `github.com/mistcash/polynomial-ring-toolkit`, with the
  package at `polyring/`. No dependency on grosh26 remains: gnark's limb
  composition helpers, vendored in grosh26 as `internal/limbcomposition`,
  moved here as `internal/limbs`.
- `field_polyring.go` is split by concern into `checker.go`, `poly.go`,
  `mul.go`, `deferred.go`, `challenge.go` and `accumulator.go`, with the
  protocol written up in `doc.go` and `docs/review-spec.md` (§1 of grosh26's
  review spec, which now points here).
- The package no longer dot-imports gnark's `emulated`, so the hint accessor
  gets its conventional name: `GetPolyRingHints` is now `GetHints`. It is the
  one rename; everything else keeps the name it had.
- `NativeToEmulated` no longer assumes the emulated field has exactly as many
  limbs as a native element decomposes into. A wider field (BLS12-377's base
  field over a BN254 native field, say) pads with constant zero instead of
  failing `enforceWidth`; a field too narrow to hold the challenge at full
  width returns an error rather than silently truncating it. Behaviour for
  fields of matching width, which is every field grosh26 uses, is unchanged.
- Removed a package-level `map[int]int` that counted claimed products by
  degree. Nothing read it, and writing to it raced across concurrent circuit
  compilations.
- Tests, which the package previously had none of: the off-circuit Euclidean
  division directly, and the in-circuit protocol over rings and coefficient
  fields unrelated to any pairing, including two negative tests.
