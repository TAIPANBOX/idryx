#!/usr/bin/env bash
# Holds the vocabulary of the AI-usage report (internal/aiusage) to the places a
# reader meets it: every disagreement the report can name, and every source it
# can state, has a sentence in the code and a row in the README, and the README
# names nothing the code does not define.
#
# WHAT THIS IS NOT. It does not check that a gap is assigned to the right rows;
# the tests in internal/aiusage and cmd/idryx do that, and they were each run
# red first. It checks that the list of names is one list. A gap added to the
# code and left out of the README is a disagreement a reader sees in a table and
# finds nowhere in the docs; a README row for a name the code stopped producing
# is a promise nothing keeps. Same shape as detectors-complete.sh, for the same
# reason: a hand-kept list in two places is two lists.
#
# WHAT IT CHECKS, for the gaps (Gap* constants) and again for the sources
# (Source* constants):
#
#   1. each constant has a row in the README table between its two markers;
#   2. each README row is a constant the code defines;
#   3. each gap has a sentence in gapText, so no gap renders blank.
#
# A subject that has gone away must be said, not passed over: finding no
# constants at all is a failure that names itself.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

CODE=internal/aiusage/subjects.go
README=README.md

problems=0
note() {
	echo "FAIL: $1"
	problems=$((problems + 1))
}

[ -f "$CODE" ] || {
	echo "FAIL: $CODE is missing, so this check measured nothing"
	exit 1
}
[ -f "$README" ] || {
	echo "FAIL: $README is missing, so nothing was checked against a README"
	exit 1
}

# names <Prefix>: the string value of every constant named Prefix<Something>.
names() {
	grep -E "^[[:space:]]+${1}[A-Za-z]+[[:space:]]*= \"[a-z_]+\"" "$CODE" |
		sed -E 's/.*= "([a-z_]+)".*/\1/' | sort -u
}

# rows <marker>: the first-column name of every table row between the markers.
rows() {
	awk -v b="<!-- ${1}:begin -->" -v e="<!-- ${1}:end -->" '
		index($0, b) { on = 1; next }
		index($0, e) { on = 0 }
		on && /^\| `[a-z_]+` \|/ { print }
	' "$README" | sed -E 's/^\| `([a-z_]+)`.*/\1/' | sort -u
}

check() {
	local kind="$1" prefix="$2" marker="$3" defined documented
	defined=$(names "$prefix")
	documented=$(rows "$marker")
	if [ -z "$defined" ]; then
		note "no $kind constants found in $CODE, which means this check measured nothing"
		return
	fi
	if [ -z "$documented" ]; then
		note "the README has no $kind table between <!-- ${marker}:begin --> and <!-- ${marker}:end -->, so nothing was compared"
		return
	fi
	while IFS= read -r n; do
		[ -n "$n" ] || continue
		grep -qx "$n" <<<"$documented" ||
			note "$kind '$n' is defined in $CODE and has no row in the README table"
	done <<<"$defined"
	while IFS= read -r n; do
		[ -n "$n" ] || continue
		grep -qx "$n" <<<"$defined" ||
			note "the README documents $kind '$n' and $CODE defines no such name"
	done <<<"$documented"
}

check gap Gap usage-gaps
check source Source usage-sources

# Every gap has a sentence. gapText is keyed by the constant, so read the
# constants' names and look for their keys.
gap_consts=$(grep -E '^[[:space:]]+Gap[A-Za-z]+[[:space:]]*= "' "$CODE" | sed -E 's/^[[:space:]]+(Gap[A-Za-z]+).*/\1/')
while IFS= read -r c; do
	[ -n "$c" ] || continue
	grep -qE "^[[:space:]]+${c}:[[:space:]]+\"" "$CODE" ||
		note "gap $c has no sentence in gapText, so a report would render it blank"
done <<<"$gap_consts"

if [ "$problems" -ne 0 ]; then
	echo
	echo "A name the report can print and the docs do not list is a disagreement a reader cannot look up."
	echo "See AGENTS.md, hard invariants."
	exit 1
fi

g=$(names Gap | wc -l | tr -d ' ')
s=$(names Source | wc -l | tr -d ' ')
echo "OK: $g gaps and $s sources, each in the code with a sentence and in the README, and nothing documented that the code lacks."
