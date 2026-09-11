#!/bin/sh
# Bench the Groth16-simulation pairing check (ring vs gnark) with full
# profiles, then sweep the other benchmarks for constraint counts.
#
# Artifacts in OUTDIR, per circuit (groth16sim-ring, groth16sim-gnark):
#   *.cpu.{out,pdf}, *.mem.{out,pdf}  Go runtime profiles of the benchmark
#   *.pprof                           gnark constraint/operation profiles
#   *.constraints.pdf                 gnark profile, sample_index=constraints
#   *.operations.pdf                  gnark profile, sample_index=operations
#   *.bench.log                       benchmark output (constraint counts)
# plus constraints.txt (per-phase breakdown) and other-benches.log.
#
# Usage:
#   ./lib/profile/pprof-groth16sim.sh
#
# Env:
#   BENCHTIME  per-benchmark time, e.g. 10x, 30s (default: 10x)
#   OUTDIR     output directory (default: profiles/groth16sim)
#
# Requires graphviz (dot) for the PDF steps.
set -eu

PROJECT_ROOT="$(dirname "$0")/../.."

cd $PROJECT_ROOT

BENCHTIME="${BENCHTIME:-10x}"
OUTDIR="${OUTDIR:-$(dirname "$0")/profiles/groth16sim}"

# Absolutize: the test binary runs with the package dir as its cwd, so a
# relative OUTDIR would scatter artifacts (e.g. gnark profiles) there.
case "$OUTDIR" in
/*) ;;
*) OUTDIR="$(pwd)/$OUTDIR" ;;
esac

command -v dot >/dev/null 2>&1 || {
	echo "error: graphviz 'dot' not found (needed by 'go tool pprof -pdf')" >&2
	exit 1
}
command -v go >/dev/null 2>&1 || {
	echo "error: go not found" >&2
	exit 1
}

mkdir -p "$OUTDIR"

# Compile the test binary once so the profiles stay symbolized.
TESTBIN="$OUTDIR/profile.test"
go test -c -o "$TESTBIN" ./lib/profile

simprofile() {
	name="$1" # groth16sim-ring | groth16sim-gnark
	sub="$2"  # ring | gnark
	echo "== $name (benchtime=$BENCHTIME)"
	GNARK_PROFILE_DIR="$OUTDIR" "$TESTBIN" \
		-test.run '^$' \
		-test.bench "BenchmarkGroth16Sim/$sub" \
		-test.benchtime "$BENCHTIME" \
		-test.count 1 \
		-test.v \
		-test.cpuprofile "$OUTDIR/$name.cpu.out" \
		-test.memprofile "$OUTDIR/$name.mem.out" \
		2>&1 | tee "$OUTDIR/$name.bench.log"
	go tool pprof -pdf -output "$OUTDIR/$name.cpu.pdf" "$TESTBIN" "$OUTDIR/$name.cpu.out"
	go tool pprof -pdf -output "$OUTDIR/$name.mem.pdf" "$TESTBIN" "$OUTDIR/$name.mem.out"
	go tool pprof -pdf -sample_index=constraints -output "$OUTDIR/$name.constraints.pdf" "$OUTDIR/$name.pprof"
	go tool pprof -pdf -sample_index=operations -output "$OUTDIR/$name.operations.pdf" "$OUTDIR/$name.pprof"
}

simprofile groth16sim-ring ring
simprofile groth16sim-gnark gnark

echo "== other benches (counts only)"
TEST_RESULTS=$(go test ./... -run '^$' -bench '.' -benchtime=1x -count=1 -v 2>&1)
mkdir -p "$PROJECT_ROOT/bench"
echo "$TEST_RESULTS" | grep -E "groth16sim_test.go|BenchmarkGroth16Sim" | tee "$PROJECT_ROOT/bench/groth16-delta.txt"
echo "$TEST_RESULTS" | grep -E "groth16sim_test.go|BenchmarkGroth16Sim|constraints|^(--- FAIL|FAIL|ok )"

echo "done: $OUTDIR"
