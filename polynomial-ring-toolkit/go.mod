module github.com/mistcash/polynomial-ring-toolkit

go 1.26.2

require (
	github.com/consensys/gnark v0.16.0
	github.com/consensys/gnark-crypto v0.21.0
)

require (
	github.com/bits-and-blooms/bitset v1.24.6 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// gnark comes from tiny-gnark's pre-merge branch, a fork that keeps the
// upstream module path so every import still reads github.com/consensys/gnark.
// The fix this module needs is in frontend/cs/r1cs, where builder.Commit looked
// an already-committed wire's commitment up in a list it had partly consumed.
// The deferred ring check draws two commitments before the range checker draws
// its own, which is enough to make stock gnark pick the wrong one or run off
// the end.
replace github.com/consensys/gnark v0.16.0 => github.com/mistcash/tiny-gnark v0.0.0-20260823021757-e5aa518e2e6e
