#!/usr/bin/env bash
# Holds two properties of the detector set that are true today and would break
# silently.
#
# WHAT THIS IS NOT. It does not check that a detector can fire; the per-detector
# tests do that, and they do it properly (every detector has a test file, and
# the ones sampled assert "expected a finding, got none" rather than merely
# running without panicking). An earlier attempt at this script tried to judge
# that by pattern-matching the test source and produced a confidently wrong
# number, which is why it does not do that any more. A check that cannot tell a
# helper-based assertion from an absent one should not be counting.
#
# WHAT IT DOES CHECK:
#
#   1. Every detector defined in internal/detect/detectors is registered in
#      cmd/idryx/main.go. The registry is a hand-maintained list. A detector
#      that exists and is never registered never runs, and it looks like
#      coverage in every review: the file is there, the tests pass, and no
#      identity graph is ever shown to it.
#
#   2. Every detector has a test file. Not proof it fires, but a new detector
#      arriving with no test at all should not be a thing a reviewer has to
#      notice.
#
# Both are true right now. That is the point: this is a ratchet against a
# regression, not a repair.
#
# This file is the ONE copy of this check.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

DETECTORS=internal/detect/detectors
REGISTRY=cmd/idryx/main.go

problems=0
note() {
	echo "FAIL: $1"
	problems=$((problems + 1))
}

[ -d "$DETECTORS" ] || {
	echo "FAIL: $DETECTORS is missing, so this check measured nothing"
	exit 1
}
[ -f "$REGISTRY" ] || {
	echo "FAIL: $REGISTRY is missing, so nothing was checked against a registry"
	exit 1
}

defined=$(grep -rhoE '^func New[A-Za-z]+\(' "$DETECTORS"/*.go 2>/dev/null |
	grep -v '_test' | sed 's/^func //; s/($//; s/(//' | sort -u)

registered=$(grep -oE 'detectors\.New[A-Za-z]+' "$REGISTRY" |
	sed 's/detectors\.//' | sort -u)

if [ -z "$defined" ]; then
	note "no detector constructors found at all, which means this check measured nothing"
fi
if [ -z "$registered" ]; then
	note "no detector is registered in $REGISTRY, which means this check measured nothing"
fi

while IFS= read -r d; do
	[ -n "$d" ] || continue
	if ! grep -qx "$d" <<<"$registered"; then
		note "$d is defined but never registered in $REGISTRY. It never runs, and it looks like coverage: the file is there and its tests pass, but no identity graph is ever shown to it."
	fi
done <<<"$defined"

while IFS= read -r r; do
	[ -n "$r" ] || continue
	if ! grep -qx "$r" <<<"$defined"; then
		note "$r is registered in $REGISTRY but no constructor of that name exists in $DETECTORS"
	fi
done <<<"$registered"

# Every detector source file needs a test file beside it.
for f in "$DETECTORS"/*.go; do
	b=$(basename "$f" .go)
	case "$b" in *_test) continue ;; esac
	if [ ! -f "$DETECTORS/${b}_test.go" ]; then
		note "$b has no test file. Whether its tests prove it can fire is a matter for review, but arriving with none should not be."
	fi
done

if [ "$problems" -ne 0 ]; then
	echo
	echo "A detector nobody registers is dead code that reads as coverage."
	echo "See AGENTS.md, hard invariants."
	exit 1
fi

n=$(wc -l <<<"$defined" | tr -d ' ')
echo "OK: $n detectors, every one registered and every one with a test file."
