#!/usr/bin/env sh
# fuzz-smoke.sh PKG TARGET [DURATION]
#
# Runs one fuzz target briefly, e.g.  ./scripts/fuzz-smoke.sh ./frost FuzzVerify 5s
#
# A genuine failure makes the Go fuzz engine write the failing input to
# PKG/testdata/fuzz/TARGET/ and is always reported. The engine also sometimes
# reports "context deadline exceeded" when a worker is still minimizing an
# input as the time budget runs out under load; that leaves no recorded input
# and is not a finding, so a failure without a recorded input is retried once.
set -u

pkg=$1
target=$2
duration=${3:-5s}
crashdir="$pkg/testdata/fuzz/$target"

run() {
	go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$duration"
}

if run; then
	exit 0
fi
if [ -d "$crashdir" ] && [ -n "$(ls -A "$crashdir" 2>/dev/null)" ]; then
	echo "fuzz-smoke: $target recorded a failing input in $crashdir" >&2
	exit 1
fi
echo "fuzz-smoke: $target failed without a recorded input; retrying once" >&2
run
