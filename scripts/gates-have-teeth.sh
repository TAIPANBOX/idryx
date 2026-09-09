#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY THE THIRD ONE IS HERE
#
# A correction first, because this header was wrong about its sibling. It said
# tokenfuse's version of this script does not assert the third property. It
# does, on four cases, and had before this one was written. What was true is
# that tokenfuse's HEADER documents only two, which is how the claim survived a
# reading: the prose there agreed with me and the code did not. Checked on
# 2026-08-09 by reading that file rather than remembering it, and now covered
# there on seven cases across all eight of its gates.
#
# Over 8-9 August 2026 one mistake was made nine times in this repository's
# tooling, and never once in the product code: a check that cannot tell "did not
# fail" from "did not run". Twice it accused working code.
#
#   - A mutation removed a branch, left an import unused, the package stopped
#     compiling, the test never ran, and a grep for FAIL read that silence as a
#     pass. Three times.
#   - A mutation searched for text the code did not contain, changed nothing,
#     tests passed against CORRECT code, and the harness printed "THE MUTATION
#     PASSED. The test proves nothing", blaming a test that worked.
#   - A live run printed two "must be 0" lines that were empty rather than zero,
#     because they read a field name that does not exist. Empty and zero look
#     identical.
#   - And in the very script written to fix that, twenty lines below the fix,
#     two sections printed nothing because a helper taking one argument was
#     called with a flag.
#
# The lesson is not "be careful". Being careful failed nine times. What survived
# every one of those oversights were the steps carrying an explicit comparison
# and a non-zero exit. What broke every time were the lines that only printed.
#
# So this harness asserts three things per gate where each applies: it fails on
# a real fault, it does not fail on a non-fault, and when its subject is taken
# away it says so instead of reporting OK.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success.
#
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# No case proves anything if the gate was already failing before the mutation.
# So every case runs the gate on the UNMUTATED tree first and reports
# UNJUDGEABLE. Found on 2026-08-09 in it-rat, where one gate was legitimately
# red and a case against it would have been indistinguishable from a working
# one.
#
# It covered only the fail-cases at first, which left the mirror of the same
# bug: on a red gate a pass-case reports OVEREAGER, "the gate failed on
# something it must not catch", and sends the reader to look at a harmless
# mutation. The verdict was being given without the predicate it depends on.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file. A case whose edit applied nothing is a
# failure here, not a pass. That is the second bullet above, and it is the one
# that sent a whole run chasing a working test.
#
# WHAT IT FOUND, AND WHAT THAT MEANS
#
# No hole in any of the five gates. Two of the thirteen cases had to be
# rewritten because the MUTATION was wrong, not the gate: one searched for an
# asset name the workflow spells differently, and one removed a build tag from
# a file also named *_linux.go, where the suffix constrains the build on its
# own and a green result was correct. Both were caught here rather than
# recorded as findings, which is the whole point of asserting that an edit
# applied.
#
# A ratchet is supposed to find nothing on the day it is installed. It is here
# so the next edit to a gate cannot quietly remove its teeth.
#
# WHAT IT CANNOT DO
#
# It cannot test itself, and nothing watches this script fail. It proves each
# gate catches the faults named here, not every fault of that kind.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

restore() { git checkout -- . 2>/dev/null; }
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first
# rather than adding to it. Writing them separately disarmed `restore` on
# every interrupt path, which would leave a mutated tree behind on Ctrl-C.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM


failures=0
cases=0
skipped_toolchain=0

# An optional name filter, so one gate's cases can be run on their own. This
# exists for object-matches-its-source.sh, whose cases need clang, llvm-strip
# and libbpf's headers: those live in ci.yml's `ebpf` job, and that job checks
# out shallow, which the diagram cases cannot survive (they compare the commit
# that last touched each SVG with the one that touched its PNG, and on a shallow
# clone both are HEAD). So the `ebpf` job runs `gates-have-teeth.sh
# object-matches-its-source` rather than the whole suite twice.
FILTER="${1:-}"

# Whether this machine can compile a BPF object at all. Checked explicitly
# rather than left to the gate's own refusal: without a toolchain that gate
# correctly reports that it measured nothing, every case against it would come
# back UNJUDGEABLE, and a harness reporting four failures on a machine that is
# simply a laptop teaches everyone to ignore it.
#
# THE LAST CLAUSE IS THE ONE THAT MATTERS, and it is not decoration. GitHub's
# ubuntu-24.04 image ships clang 18 already, and does NOT ship libbpf-dev. So
# `command -v clang` plus a version match is true in the `build` job, where the
# <bpf/bpf_helpers.h> that connect.c includes does not exist: the gate would
# refuse for a perfectly good reason, its baseline would be red, and all four
# cases would report UNJUDGEABLE in a job that never intended to run them.
# Asking whether a minimal BPF translation unit COMPILES is the same question
# the cases actually need, and costs one clang invocation.
have_bpf_toolchain=0
if command -v clang >/dev/null 2>&1 && command -v llvm-strip >/dev/null 2>&1 &&
	clang --version 2>/dev/null | grep -q 'clang version 18\.' &&
	printf '#include <bpf/bpf_helpers.h>\nchar _l[] SEC("license") = "GPL";\n' |
	clang -target bpf -O2 -c -x c - -o /dev/null >/dev/null 2>&1; then
	have_bpf_toolchain=1
fi

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The optional needle separates "it failed" from "it failed for the reason this
# case is about". Without it, a case expecting failure is satisfied by any
# failure, including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"

	if [ -n "$FILTER" ] && ! printf '%s' "$name" | grep -qF -- "$FILTER"; then
		return
	fi

	cases=$((cases + 1))

	# The baseline applies to EVERY case, not only the ones expecting a failure.
	# It was `fail`-only until 2026-08-09, which left the mirror of the bug it was
	# written for: on a gate that is already red, a `pass` case reports OVEREAGER,
	# "the gate failed on something it must not catch", and sends the reader to
	# look at a harmless mutation while the gate was failing without it. Neither
	# verdict means anything on a red gate, so neither is given.
	skip_baseline=0
	if [ "$expect" = fail_env ]; then
		# `fail` with the baseline skipped, for cases whose fault IS the command
		# rather than a mutation: red before and after is the point there.
		expect=fail
		skip_baseline=1
	fi

	if [ "$skip_baseline" = 0 ]; then
		local key base_out
		key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
		if [ ! -f "$key" ]; then
			if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
		fi
		base_out="$(cat "$key")"
		if [ "$base_out" = red ]; then
			printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so neither a\n             failure nor a pass after the mutation would prove anything\n' "$name"
			failures=$((failures + 1))
			return
		fi
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
		printf '%s\n' "$out" | head -4 | sed 's/^/           /'
	else
		printf 'ok  %-56s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

# The same, for cases that cannot run without a compiler that emits BPF. A
# machine without one records the case as NOT RUN and names the job that runs
# it, which is a different statement from a pass and is printed as one. The
# distinction is the whole subject of this file, so it would be a poor place to
# let a skip wear a pass's clothes.
run_case_bpf() {
	if [ "$have_bpf_toolchain" = 1 ]; then
		run_case "$@"
		return
	fi
	if [ -n "$FILTER" ] && ! printf '%s' "$1" | grep -qF -- "$FILTER"; then
		return
	fi
	skipped_toolchain=$((skipped_toolchain + 1))
	printf 'NOT RUN  %s\n         needs clang 18 with the BPF target and libbpf headers;\n         ci.yml runs it in the `ebpf` job\n' "$1"
}

echo "=== faults each gate must catch ==="

run_case "readme-numbers: a stale test badge" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"tests-(\d+)-brightgreen", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "tests-%d-brightgreen" % (int(m.group(1))+7), 1))')" \
	"badge"

run_case "detectors-complete: a detector nobody registered" fail \
	'./scripts/detectors-complete.sh' \
	"$(py 'edit("cmd/idryx/main.go", "detectors.NewBeaconing(),", "")')" \
	"NewBeaconing is defined but never registered"

run_case "diagrams: a stale headline count" fail \
	'./scripts/diagrams-match-detectors.sh' \
	"$(py 'import re
s = open("docs/detectors.svg").read()
m = re.search(r"(\d+) deterministic detectors", s)
assert m, "no count in detectors.svg"
open("docs/detectors.svg","w").write(s.replace(m.group(0), "%d deterministic detectors" % (int(m.group(1))-6), 1))')" \
	"detectors"

run_case "diagrams: a correct headline over a stale breakdown" fail \
	'./scripts/diagrams-match-detectors.sh' \
	"$(py 'import re
s = open("docs/architecture.svg").read()
m = re.search(r"agents/AI x(\d+)", s)
assert m, "no per-family breakdown in architecture.svg"
open("docs/architecture.svg","w").write(s.replace(m.group(0), "agents/AI x%d" % (int(m.group(1))-3), 1))')" \
	"one picture, two answers"

run_case "ebpf-optional: the OS constraint lost from a generated file" fail \
	'./scripts/ebpf-optional.sh' \
	"$(py 'edit("internal/ebpfcapture/bpf_bpfel.go", "//go:build linux && (", "//go:build (")')" \
	"cilium/ebpf packages"

run_case "reproducible-build: a version back in the asset name" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "out=\"idryx_", "out=\"idryx_${VERSION}_")')" \
	"VERSION"

run_case_bpf "object-matches-its-source: connect.c edited, object not regenerated" fail \
	'./scripts/object-matches-its-source.sh' \
	"$(py 'edit("internal/ebpfcapture/bpf/connect.c", "__uint(max_entries, 256 * 1024);", "__uint(max_entries, 512 * 1024);")')" \
	"not what the committed C compiles to"

echo
echo "=== and what they must NOT catch ==="

run_case "diagrams: prose edited around the count" pass \
	'./scripts/diagrams-match-detectors.sh' \
	"$(py 'edit("README.md", "## What it does", "## What it does\n\n<!-- a harmless prose edit -->")')"

run_case "detectors-complete: a comment added beside the registry" pass \
	'./scripts/detectors-complete.sh' \
	"$(py 'edit("cmd/idryx/main.go", "detectors.NewBeaconing(),", "// a harmless comment\n\t\tdetectors.NewBeaconing(),")')"

# Deliberately an edit on the GO side, not a comment in connect.c. Under `-g`
# the compiled object carries BTF line information, so editing even a comment in
# the C genuinely changes the bytes and the object genuinely does need
# regenerating. This case exists to prove the gate is not simply always red,
# which is what a pass-case is for.
run_case_bpf "object-matches-its-source: prose edited on the Go side of the sensor" pass \
	'./scripts/object-matches-its-source.sh' \
	"$(py 'edit("internal/ebpfcapture/capture_linux.go", "// Options configures Run.", "// Options configures Run. A harmless prose edit.")')"

echo
echo "=== and the one this repository learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "detectors-complete: no detectors to find" fail \
	'./scripts/detectors-complete.sh' \
	"$(py 'import re, pathlib
p = pathlib.Path("internal/detect/detectors/beaconing.go")
s = p.read_text()
# take every constructor out of the package: the gate must notice it is
# measuring an empty set rather than congratulating it
import glob
for f in glob.glob("internal/detect/detectors/*.go"):
    if f.endswith("_test.go"):
        continue
    t = open(f).read()
    open(f, "w").write(re.sub(r"^func New[A-Za-z]+\(\)", "func disabled_New()", t, flags=re.M))
')" \
	"measured nothing"

run_case "diagrams: no detector names to count" fail \
	'./scripts/diagrams-match-detectors.sh' \
	"$(py 'import re, glob
for f in glob.glob("internal/detect/detectors/*.go"):
    if f.endswith("_test.go"):
        continue
    t = open(f).read()
    open(f, "w").write(re.sub(r"Name\(\) string \{ return \"[a-z_]+\"", "Name() string { return \"\"", t))
')" \
	"measured nothing"

run_case "reproducible-build: no asset name left to read" fail \
	'./scripts/reproducible-build.sh' \
	"$(py 'edit(".github/workflows/release.yml", "out=\"idryx_", "unused=\"idryx_")')" \
	"A missing subject is not a pass"

run_case "readme-numbers: no badge left to check" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"!\[[^]]*\]\(https://img.shields.io/badge/tests-\d+-brightgreen[^)]*\)", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "", 1))')" \
	"nothing to compare against"

run_case_bpf "object-matches-its-source: no committed object left to compare" fail \
	'./scripts/object-matches-its-source.sh' \
	"$(py 'import os
os.remove("internal/ebpfcapture/bpf_bpfel.o")')" \
	"measured nothing"

# The pin itself, which is the part of that gate most easily removed by somebody
# tidying up. clang changes its output between versions (measured 2026-09-09:
# 18.1.3 drops two redundant register initialisations the committed object
# carried), so a comparison made with an unpinned compiler answers a different
# question and must refuse rather than report OK. `fail_env` because the fault is
# the command, not a mutation: nothing is edited, and the edit below only asserts
# the case is meaningful.
run_case_bpf "object-matches-its-source: a compiler that is not the pinned one" fail_env \
	'BPF2GO_CC=python3 ./scripts/object-matches-its-source.sh' \
	"$(py 'import re, subprocess
r = subprocess.run(["python3", "--version"], capture_output=True, text=True)
m = re.search(r"[0-9]+\.[0-9]+\.[0-9]+", r.stdout + r.stderr)
assert m, "python3 reports no version, so it cannot stand in for a wrong compiler"
assert not m.group(0).startswith("18."), "python3 reports 18.x, the pinned clang version, so this case proves nothing"')" \
	"was built with clang"

run_case "ebpf-optional: nothing pulling in cilium on linux either" fail \
	'./scripts/ebpf-optional.sh' \
	"$(py 'for f in ["internal/ebpfcapture/capture_linux.go",
          "internal/ebpfcapture/bpf_bpfel.go",
          "internal/ebpfcapture/bpf_bpfeb.go"]:
    t = open(f).read()
    i = t.index("//go:build ")
    j = t.index(chr(10), i)
    assert "linux" in t[i:j], "no linux constraint in " + f
    open(f, "w").write(t[:i] + "//go:build never_built" + t[j:])')" \
	"pulls in NO cilium/ebpf packages"

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$skipped_toolchain" -gt 0 ]; then
	printf '%d case(s) above did not run on this machine, which is not the same as\n' "$skipped_toolchain"
	printf 'passing. They need a compiler that emits BPF, and ci.yml runs them in the\n'
	printf '`ebpf` job:  ./scripts/gates-have-teeth.sh object-matches-its-source\n'
	printf '\n'
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
