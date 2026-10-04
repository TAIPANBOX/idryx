#!/usr/bin/env bash
# Every scenario in features/ names a test that exists, and every scenario names
# one at all.
#
# WHY BOTH DIRECTIONS
#
# A scenario bound to nothing is a paragraph describing what somebody wanted,
# and it proves nothing about what the code does. A binding pointing at a test
# that has been renamed or deleted is worse than none: it reads as held, and a
# reader has no way to tell without grepping. Two different lies, and only one
# of them is visible from either side alone.
#
# WHY NOT A BDD RUNNER
#
# The ask the scenarios serve is readability: a person reads Given / When /
# Then instead of a diff. A runner would add a step-definition style to this
# repository for that, and the binding gate delivers the readable half at a
# fraction of the surface. The same decision agent-stack-go, tokenfuse, vouchryx
# and heraldyx made; this script is agent-stack-go's, copied here when this
# repository got its first features/ directory.
#
# WHAT THIS DOES NOT DO
#
# It does not check that a test ASSERTS what its scenario says, and nothing
# mechanical can: the steps are prose and the binding is a pointer. What it
# catches is the pointer breaking, which is the failure that happens on its own
# while nobody is looking.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ ! -d features ]; then
	echo "FAIL: features/ is gone, so this gate measured nothing" >&2
	exit 1
fi

scenarios=$(grep -ch '^  Scenario:' features/*.feature 2>/dev/null | awk '{s += $1} END {print s + 0}')
bindings=$(grep -ch '^  # @test:' features/*.feature 2>/dev/null | awk '{s += $1} END {print s + 0}')

if [ "$scenarios" -eq 0 ]; then
	# A subject that has gone away must say so rather than report OK on
	# nothing. This is the property AGENTS.md invariant 9 is about.
	echo "FAIL: no scenarios found in features/, so this gate measured nothing" >&2
	exit 1
fi

broken=0
while read -r name; do
	[ -n "$name" ] || continue
	if ! grep -rq "func ${name}(" --include='*_test.go' .; then
		echo "FAIL: features name ${name} and no such test exists" >&2
		broken=$((broken + 1))
	fi
done < <(grep -h '^  # @test:' features/*.feature | sed 's/.*@test://')

if [ "$scenarios" != "$bindings" ]; then
	echo "FAIL: ${scenarios} scenario(s) and ${bindings} binding(s)" >&2
	broken=$((broken + 1))
fi

[ "$broken" -eq 0 ] || exit 1
echo "features: ${scenarios} scenarios, ${bindings} bindings, 0 broken"
