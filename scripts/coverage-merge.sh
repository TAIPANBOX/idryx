#!/usr/bin/env bash
# Merge Go coverage profiles into one: per block, the highest count wins, so a
# statement counts as covered when ANY run executed it.
#
#   coverage-merge.sh <out> <profile> [<profile>...]
#
# All profiles must carry the same "mode:" line and the same block set per
# file (same sources). A missing or empty input is MEASURED NOTHING and fails:
# a merge that silently drops one run would report the other's number as the
# total.
set -euo pipefail
[ "$#" -ge 2 ] || { printf 'usage: %s <out> <profile>...\n' "$0" >&2; exit 2; }
out="$1"; shift
for f in "$@"; do
	first=""
	[ ! -s "$f" ] || IFS= read -r first <"$f" || true
	if [ "${first#mode: }" = "$first" ]; then
		printf 'MEASURED NOTHING: %s is missing, empty or not a coverage profile\n' "$f" >&2
		exit 1
	fi
done
awk '
FNR == 1 {
	if (mode != "" && $0 != mode) { print "mode mismatch: " $0 " vs " mode > "/dev/stderr"; bad = 1; exit 1 }
	mode = $0; next
}
{
	n = split($0, p, " ")
	if (n != 3) { print "malformed line: " $0 > "/dev/stderr"; bad = 1; exit 1 }
	key = p[1] " " p[2]
	if (!(key in cnt)) order[++k] = key
	if (!(key in cnt) || p[3] + 0 > cnt[key] + 0) cnt[key] = p[3]
}
END {
	if (bad) exit 1
	print mode
	for (i = 1; i <= k; i++) print order[i] " " cnt[order[i]]
}' "$@" >"$out.tmp"
mv "$out.tmp" "$out"
