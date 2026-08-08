#!/usr/bin/env bash
# Every number the diagrams state about the detector set, checked against the
# detector set.
#
# WHY THIS EXISTS, AND IT IS NOT HYPOTHETICAL
#
# docs/detectors.svg said "17 deterministic detectors" and docs/architecture.svg
# said "17 detectors" from 10 July 2026 until 8 August. The repository had 22 by
# early August and 23 by the end of that day. Nothing noticed for a month,
# because no gate reads an image: readme-numbers.sh checks the README's own
# figures, detectors-complete.sh checks that every detector is registered and
# tested, and between them the SVGs are seen by nobody. The drift was found by a
# person redrawing the pictures for an unrelated reason.
#
# The second half of that story is why the per-family breakdown is checked too.
# architecture.svg carries "ITDR x4 . NHI x5 . agents/AI x7 . least_privilege"
# further down the same picture, which summed to 17 while the headline had just
# been corrected to 23. One image, two answers. A check on the headline alone
# would have gone green over it.
#
# WHAT IT READS
#
#   1. The detector names, from their own Name() methods in
#      internal/detect/detectors. Not from the README, which is a copy, and not
#      from the constructor names, which are a spelling of the same thing one
#      transformation away.
#   2. The families, from the README's detector table, keyed on those names.
#      The README is the only place families are written down at all; where it
#      is the source, it is used, and where it is a copy (the count), it is not.
#   3. Every "<N> detectors", "<N> deterministic detectors" and "<N> rules" in
#      docs/*.svg, and the "family xN" breakdown.
#   4. Whether the PNG beside each SVG moved in the same commit, because the
#      README embeds the PNG and nothing else here can see inside one.
#
# WHAT IT CANNOT DO, said plainly rather than left to be assumed
#
# It does not look at a pixel. A PNG regenerated from a stale SVG, or one
# rendered at the wrong scale, or one that failed halfway and wrote a blank
# canvas, passes this cleanly. What it holds is narrower and is the failure that
# actually happened: a number in the source that no longer matches the code, and
# a picture that was never re-rendered after its source changed.
#
# It also does not read the card contents ("excessive_agency . shadow_ai +5
# more"). Those are prose-shaped: "+5 more" is relative to two names that are
# themselves a choice, and a script that guessed at which detectors belong on
# which card would cry wolf and get switched off. That half is a reader's job,
# and this comment is where they are told so.
#
# This file is the ONE copy of this check.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

DETECTORS=internal/detect/detectors
README=README.md

problems=0
note() {
	echo "FAIL: $1"
	problems=$((problems + 1))
}

[ -d "$DETECTORS" ] || {
	echo "FAIL: $DETECTORS is missing, so this check measured nothing"
	exit 1
}

# ------------------------------------------------------- 1. the detector set
#
# From the Name() methods themselves. A detector's name is the string it puts
# in every alert it emits, so this is the same value an operator sees, not a
# transformation of a Go identifier that could differ from it.
names=$(grep -rhoE 'func \(d \*[A-Za-z]+\) Name\(\) string \{ return "[a-z_]+"' \
	"$DETECTORS"/*.go 2>/dev/null | grep -v '_test' |
	sed 's/.*return "//; s/"$//' | sort -u)
count=$(printf '%s\n' "$names" | grep -c .)

if [ "$count" -lt 2 ]; then
	echo "FAIL: found $count detector name(s), which means this check measured nothing."
	echo "      It reads 'func (d *X) Name() string { return \"...\" }' out of $DETECTORS."
	exit 1
fi

# ------------------------------------------------- 2. families, from the README
#
# Only for names the code defines: the README's table also lists connectors and
# graph fields, and counting those would inflate every family.
# `declare -A` is bash 4; macOS ships 3.2, and a gate that only runs on the CI
# runner is a gate nobody runs before pushing. That is the exact shape of three
# failures this repository had in one day, so this counts with a function
# instead.
family_of() {
	grep -oE "^\| \`$1\` \| [^|]+" "$README" 2>/dev/null | head -1 |
		sed "s/^| \`$1\` | //; s/ *$//"
}

count_in_family() {
	local want="$1" n=0 fam
	for d in $names; do
		fam=$(family_of "$d")
		[ "$fam" = "$want" ] && n=$((n + 1))
	done
	echo "$n"
}

missing_family=""
for n in $names; do
	[ -z "$(family_of "$n")" ] && missing_family="$missing_family $n"
done
if [ -n "$missing_family" ]; then
	note "these detectors have no row in the README's table, so their family is unknown
      and the per-family figures below cannot be complete:$missing_family"
fi

# --------------------------------------------------- 3. the numbers in the SVGs
for svg in docs/detectors.svg docs/architecture.svg; do
	[ -f "$svg" ] || {
		note "$svg is gone; a check that goes green once its subject has vanished is worse than no check"
		continue
	}
	# "<N> detectors", "<N> deterministic detectors", "<N> rules". Every such
	# figure in these two files is about the detector set.
	found=0
	while read -r stated; do
		[ -z "$stated" ] && continue
		found=$((found + 1))
		if [ "$stated" -ne "$count" ]; then
			note "$svg states $stated where the repository defines $count detectors.
      Re-render it: the README embeds the PNG, so editing the SVG alone changes nothing a reader sees."
		fi
	done < <(grep -oE '[0-9]+ (deterministic )?(detectors|rules)' "$svg" | grep -oE '^[0-9]+')
	if [ "$found" -eq 0 ]; then
		note "$svg states no detector count at all. It used to, and a diagram that stops
      saying how many there are is how this check stops protecting anything."
	fi
done

# ------------------------------------------- 4. the per-family breakdown
#
# architecture.svg spells it "ITDR x4", "NHI x5", "agents/AI x13". The labels
# are the diagram's own shorthand rather than the README's family strings, so
# the mapping is written here and any label this script does not know about is
# reported rather than skipped.
ARCH=docs/architecture.svg
if [ -f "$ARCH" ]; then
	while read -r label stated; do
		case "$label" in
		ITDR) expected=$(count_in_family "ITDR") ;;
		NHI) expected=$(count_in_family "NHI") ;;
		agents/AI) expected=$(count_in_family "Agents / AI") ;;
		*)
			note "$ARCH has a family label this check does not know: '$label x$stated'.
      Add it to the mapping in $0 or the breakdown is only partly checked."
			continue
			;;
		esac
		if [ "$stated" -ne "$expected" ]; then
			note "$ARCH says '$label x$stated' where the README puts $expected detectors in that family.
      This is the half a headline-only check misses: one picture, two answers."
		fi
	done < <(grep -oE '(ITDR|NHI|agents/AI) x[0-9]+' "$ARCH" | sed 's/ x/ /')
fi

# --------------------------------- 5. the PNG moved with the SVG that made it
#
# The README embeds the PNG. An SVG corrected and never re-rendered leaves the
# picture a reader actually sees exactly as wrong as before, and every check
# above passes.
for base in detectors architecture; do
	svg="docs/$base.svg"
	png="docs/$base.png"
	[ -f "$svg" ] && [ -f "$png" ] || continue
	svg_commit=$(git log -1 --format=%H -- "$svg" 2>/dev/null)
	png_commit=$(git log -1 --format=%H -- "$png" 2>/dev/null)
	if [ -n "$svg_commit" ] && [ "$svg_commit" != "$png_commit" ]; then
		note "$svg last changed in ${svg_commit:0:8} and $png in ${png_commit:0:8}.
      The README shows the PNG, so an un-rendered SVG fix reaches nobody. Re-render and commit both together."
	fi
done

if [ "$problems" -gt 0 ]; then
	echo
	echo "The diagrams are read by everyone who opens this repository and by nothing else."
	echo "Rendering, for the record: headless Chrome, --force-device-scale-factor=2,"
	echo "--window-size=1280,720, to keep the existing 2560x1440."
	exit 1
fi

echo "OK: $count detectors; every count in docs/*.svg agrees, the per-family"
echo "    breakdown sums to it, and each PNG was re-rendered with its SVG."
