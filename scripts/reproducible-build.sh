#!/usr/bin/env bash
# Enforces invariant 9 of CLAUDE.md: a released binary can be rebuilt, by
# somebody who does not trust us, from the tag it claims to come from.
#
# WHY THIS IS WORTH A GATE RATHER THAN A SENTENCE
#
# Qryx is a scanner. Its whole pitch is that you point it at your own code,
# binaries, containers and KMS and believe what it reports. A buyer's security
# team is exactly the reader who should not have to take our binary on trust,
# and the answer to them is not "the source is open" (it always was) but "build
# it yourself and check you got the same bytes we published".
#
# That answer was already TRUE on 2026-08-05 and written down nowhere. The
# release workflow builds with CGO_ENABLED=0, -trimpath and -ldflags "-s -w",
# which is what makes it hold, and any one of those three going missing would
# break it silently: nothing fails, the binaries simply stop matching, and the
# only person who finds out is the one who tried to verify us.
#
# Measured that day, to be sure the claim is not aspirational:
#   published  idryx_v0.3.0_darwin_arm64 from the release page, built on an
#              ubuntu runner cross-compiling to darwin/arm64
#   local      the same tag, checked out and built on macOS
#   sha256     8c968574341f48775e898770e98cb586b620101668b86edec24428612e979a80
# Different machine, different host OS, identical bytes.
#
# WHAT THIS CHECKS, AND WHAT IT CANNOT
#
# It builds the same target twice from two directories of DIFFERENT LENGTHS and
# refuses if a byte differs. Different lengths on purpose: two paths of the same
# length would hide a length-dependent embedding, which is the exact failure
# -trimpath exists to prevent.
#
# It proves PATH INDEPENDENCE, which is not the same statement as "this matches
# the release", and the two are worth keeping apart. It builds from `git
# archive`, so there is no `.git` and Go stamps no VCS metadata; the release is
# built in a checkout and IS stamped. The stamp is deterministic given the
# commit, so the release-matching claim in the README holds and was measured
# directly against the published artifact. This gate holds the property that
# makes that possible, on every push, without the network.
#
# HOW TO MEASURE THE STRONGER CLAIM, and the trap in doing it.
#
# Build in a real checkout at the tag: `git checkout v0.3.0 && go build ...`.
# NOT in a `git worktree --detach`, and NOT from a `git archive` extraction.
# Both of those leave Go unable to read the VCS, so it stamps no revision and
# records the module as `(devel)` instead of `v0.3.0`. The binary is then
# legitimately different from the release, and the difference looks enormous:
# `cmp -l` counts POSITIONS, so a version string one byte shorter shifts
# everything after it and reports megabytes of "differing bytes" for what is one
# changed field.
#
# That is worth writing down because it cost an afternoon and produced a wrong
# conclusion first. idryx was measured with the archive method, failed to match,
# and was written up as not reproducible. Built in a checkout at its tag it is
# byte-identical to its published artifact:
# 8c968574341f48775e898770e98cb586b620101668b86edec24428612e979a80, which is
# the digest above. The method was broken, not the build.
#
# It cannot prove a different toolchain produces the same bytes. Go's output is
# tied to its compiler version, `go.mod` pins one, and a digest is only
# meaningful next to the version that made it, so both are printed.
#
# It also does not reach the network. Comparing against the published artifact
# would be a better test and a worse gate: it would fail on every commit after a
# release, which is every commit.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BIN="${1:-idryx}"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

# ---------------------------------------------------------------------------
# Half one: the release workflow agrees with this script, and names its assets
# in a way the outside world can link to.
# ---------------------------------------------------------------------------

workflow=".github/workflows/release.yml"

if [ ! -f "$workflow" ]; then
	echo "FAIL: $workflow is missing."
	echo
	echo "This gate cannot compare its flags against a release that has no"
	echo "workflow, and a missing subject is not a pass."
	exit 1
fi

# Join backslash continuations before looking at anything. The build command in
# the workflow spans four physical lines, and a check that reads one line at a
# time would be judging a command it cannot see whole. That mistake has been
# made here before, twice, in stack-single's hook.
build_cmds="$(awk '
	{
		line = $0
		sub(/^[ \t]+/, "", line)
		if (cont != "") { line = cont " " line }
		if (line ~ /\\$/) { sub(/[ \t]*\\$/, "", line); cont = line; next }
		cont = ""
		print line
	}
	END { if (cont != "") print cont }
' "$workflow" | grep 'go build' || true)"

if [ -z "$build_cmds" ]; then
	echo "FAIL: no 'go build' command found in $workflow."
	echo
	echo "Either the release stopped building a binary, or this check stopped"
	echo "being able to find the one it builds. Both are reasons to stop. A"
	echo "check that goes green when its subject has vanished is worse than no"
	echo "check, because it teaches everyone to trust an answer it is no longer"
	echo "computing."
	exit 1
fi

missing=()
case "$build_cmds" in *"CGO_ENABLED=0"*) ;; *) missing+=("CGO_ENABLED=0") ;; esac
case "$build_cmds" in *"-trimpath"*) ;; *) missing+=("-trimpath") ;; esac
case "$build_cmds" in *"-s -w"*) ;; *) missing+=("-s -w") ;; esac

if [ ${#missing[@]} -ne 0 ]; then
	echo "FAIL: $workflow builds the release without: ${missing[*]}"
	echo
	echo "The command it runs:"
	echo "  $build_cmds"
	echo
	echo "This script builds with all three, so it would keep passing while the"
	echo "published binaries stopped matching a rebuild. The only person who"
	echo "would ever find out is the one who tried to verify us, which is the"
	echo "person this whole property exists for."
	exit 1
fi

echo "release flags: CGO_ENABLED=0, -trimpath, -s -w all present in $workflow"

asset_names="$(grep -E '^[[:space:]]*out=' "$workflow" || true)"

if [ -z "$asset_names" ]; then
	echo "FAIL: no release asset name (out=...) found in $workflow."
	echo
	echo "This cannot tell whether the published files are named stably if it"
	echo "cannot find where they are named. A missing subject is not a pass."
	exit 1
fi

case "$asset_names" in
*VERSION*)
	echo "FAIL: the release asset name in $workflow carries the version:"
	echo "  $(echo "$asset_names" | sed 's/^[[:space:]]*//')"
	echo
	echo "That name is a contract with something outside this repository."
	echo "it-rat.com links to /releases/latest/download/<name>, and that URL"
	echo "resolves only while the name is stable, so a version here turns every"
	echo "download link on the site into a 404 at the next tag. Nothing in CI"
	echo "would say so. The person who finds out is trying to install this."
	echo
	echo "The version belongs in the binary, where -X main.version already puts"
	echo "it and where the command reads it back."
	exit 1
	;;
esac

echo "release assets: named without a version, so /releases/latest/download holds"

# ---------------------------------------------------------------------------
# Half two: the same source in two directories produces the same bytes.
# ---------------------------------------------------------------------------

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

short="$work/a"
long="$work/one-rather-longer-directory-name"

for dir in "$short" "$long"; do
	mkdir -p "$dir"
	# Everything git tracks and nothing it does not: an untracked file in the
	# working tree must not be able to change the answer.
	git archive HEAD | tar -x -C "$dir"
done

echo "toolchain: $(go version)"
echo "source:    $(git rev-parse HEAD)"
echo "binary:    $BIN"

digests=()
for dir in "$short" "$long"; do
	(
		cd "$dir"
		# The same flags the release workflow uses. If these three drift apart,
		# the property this gate protects is gone and this comment is the map
		# back: CGO off so the output does not depend on a host toolchain,
		# -trimpath so the build directory is not embedded, -s -w so no build
		# id or symbol table carries a path in through the side door.
		CGO_ENABLED=0 go build -trimpath \
			-ldflags "-s -w -X main.version=${VERSION}" \
			-o "$dir/out" "./cmd/${BIN}"
	)
	if command -v sha256sum >/dev/null 2>&1; then
		digests+=("$(sha256sum "$dir/out" | cut -d' ' -f1)")
	else
		digests+=("$(shasum -a 256 "$dir/out" | cut -d' ' -f1)")
	fi
done

if [ "${digests[0]}" != "${digests[1]}" ]; then
	echo "FAIL: the same source built in two directories produced two binaries."
	echo "  ${digests[0]}  (short path)"
	echo "  ${digests[1]}  (long path)"
	echo
	echo "Something in the build is embedding the directory it ran in, so nobody"
	echo "can rebuild a release and check it against ours. Look at the flags in"
	echo "this script and in .github/workflows/release.yml: they must agree, and"
	echo "-trimpath must be in both."
	exit 1
fi

echo "reproducible: ${digests[0]}"
