#!/bin/sh
# Bench the Groth16 outer verifier (grosh26 ring pairing vs gnark, BN254 and
# BLS12-381 inner proofs) with full profiles, then sweep the other benchmarks
# for constraint counts.
#
# Artifacts in OUTDIR, per circuit (groth16-<curve>-<grosh26|gnark>):
#   *.cpu.{out,pdf}, *.mem.{out,pdf}  Go runtime profiles of the benchmark
#   *.pprof                           gnark constraint/operation profiles
#   *.constraints.pdf                 gnark profile, sample_index=constraints
#   *.operations.pdf                  gnark profile, sample_index=operations
#   *.bench.log                       benchmark output (constraint counts)
#
# Usage:
#   ./lib/profile/pprof-groth16.sh
#
# Env:
#   BENCHTIME  per-benchmark time, e.g. 10x, 30s (default: 10x)
#   OUTDIR     output directory (default: profiles/groth16)
#
# Requires graphviz (dot) for the PDF steps.
set -eu

PROJECT_ROOT="$(dirname "$0")/../.."

cd $PROJECT_ROOT

BENCHTIME="${BENCHTIME:-10x}"
OUTDIR="${OUTDIR:-$(dirname "$0")/profiles/groth16}"

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
	name="$1" # groth16-<curve>-<backend>
	sub="$2"  # sub-benchmark regex: <curve>/.*_<backend>$
	echo "== $name (benchtime=$BENCHTIME)"
	# GNARK_PROFILE_DIR="$OUTDIR" "$TESTBIN" \
	# 	-test.run '^$' \
	# 	-test.bench "BenchmarkGroth16/$sub" \
	# 	-test.benchtime "$BENCHTIME" \
	# 	-test.count 1 \
	# 	-test.v \
	# 	-test.cpuprofile "$OUTDIR/$name.cpu.out" \
	# 	-test.memprofile "$OUTDIR/$name.mem.out" \
	# 	2>&1 | tee "$OUTDIR/$name.bench.log"
	# go tool pprof -pdf -output "$OUTDIR/$name.cpu.pdf" "$TESTBIN" "$OUTDIR/$name.cpu.out"
	# go tool pprof -pdf -output "$OUTDIR/$name.mem.pdf" "$TESTBIN" "$OUTDIR/$name.mem.out"
	# go tool pprof -pdf -sample_index=constraints -output "$OUTDIR/$name.constraints.pdf" "$OUTDIR/$name.pprof"
	# go tool pprof -pdf -sample_index=operations -output "$OUTDIR/$name.operations.pdf" "$OUTDIR/$name.pprof"
}

for curve in bn254 bls12-381; do
	for backend in grosh26 gnark; do
		simprofile "groth16-$curve-$backend" "$curve/.*_$backend\$"
	done
done

ROOT_BENCH="$PROJECT_ROOT/bench"
mkdir -p "$ROOT_BENCH"
echo "== other benches"
pwd
TEST_RESULTS=$(go test ./... -run '^$' -bench '.' -benchtime=1x -count=1 -v 2>&1)
echo -e "Tests\n$TEST_RESULTS"
echo "$TEST_RESULTS" | grep -E "BENCH|BenchmarkGroth16" | tee "$ROOT_BENCH/groth16-delta.txt"
# echo "$TEST_RESULTS" | grep -E "BENCH|ns/op|allocs/op"

echo "done: $OUTDIR"
