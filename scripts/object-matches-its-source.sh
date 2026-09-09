#!/usr/bin/env bash
# Enforces invariant 14 of AGENTS.md: the committed BPF object is what the
# committed C source compiles to.
#
# WHY THIS EXISTS
#
# internal/ebpfcapture/bpf_bpfel.o and bpf_bpfeb.o are compiled binaries kept in
# git, and `//go:embed` puts them inside every binary this repository releases
# and every image it publishes. They are the one artifact here that a reviewer
# cannot read: a pull request shows "Binary files differ" and nothing else.
#
# CI compiled connect.c on every push long before this script existed, and never
# once compared the result with the committed object. It regenerated vmlinux.h
# from the runner's own kernel, ran `go generate` over the top, and built. That
# proves connect.c still COMPILES. It cannot notice that the object in the tree
# came from somewhere else, because the object in the tree is overwritten before
# anything looks at it.
#
# Measured 2026-09-09, which is why this is not hypothetical: the object
# committed on 2026-09-08 does NOT reproduce under the clang CI itself installs
# (Ubuntu clang 18.1.3, libbpf 1.3.0, the committed vmlinux.h). The rebuilt
# program is two instructions shorter, both of them a redundant `r9 = 0x0` that
# the newer compiler proves unnecessary. So the difference was benign, and that
# is exactly the point: nothing in this repository could tell that benign
# difference from a substituted program, and the person who would find out is
# whoever runs `idryx ebpf-capture` as root.
#
# WHAT IT DOES
#
# Compiles connect.c in a throwaway copy of the tree, from the COMMITTED
# vmlinux.h and with a PINNED compiler, then compares all four generated files
# with the ones in git. It never writes into the working tree, so unlike
# gates-have-teeth.sh it does not need a clean one.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
# It does not check the //go:build line of the generated Go files. bpf2go strips
# the `linux &&` prefix on every regeneration, that prefix is a deliberate
# post-generation edit, and scripts/ebpf-optional.sh already owns it with a case
# in gates-have-teeth.sh to prove it. Two gates on one property is how the two
# start disagreeing. This one removes that line from both sides before
# comparing, and fails if the committed file has no build line at all.
#
# It says nothing about whether the program is CORRECT, only that it is the
# program the C in this repository describes.
#
# THE HOST ARCHITECTURE IS NOT A VARIABLE HERE, AND THAT WAS MEASURED
#
# bpf2go compiles for bpfel and bpfeb, which are the BPF machine's two byte
# orders and have nothing to do with the machine doing the compiling. Checked
# rather than assumed on 2026-09-09, because a gate comparing digests would be
# useless if a Mac and a CI runner disagreed: the same clang 18.1.3 in an
# ubuntu:24.04 container produced identical bytes on aarch64 and on x86_64,
# db6df71e for bpfel and e808d352 for bpfeb on both. So a developer can settle a
# failure here locally and get the answer the runner will get.
#
# THE PIN, AND WHY IT IS A FEATURE THAT A COMPILER BUMP FAILS THIS
#
# clang's output for the same source changes between versions, as the two
# instructions above show. So a version this script was not pinned to cannot
# produce a comparable answer, and reporting OK after compiling with an unknown
# compiler would be a check measuring nothing. When Ubuntu moves clang, this
# goes red, and the fix is one deliberate commit: regenerate the object with the
# new compiler and move the pin in the same change. That is the event being
# made visible, not an accident to be worked around.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# The compiler this repository's committed object was built with. Moved only
# together with a regenerated object, in one commit, by somebody who looked.
EXPECTED_CLANG="18.1.3"

CC="${BPF2GO_CC:-clang}"
STRIP="${BPF2GO_STRIP:-llvm-strip}"

OBJECTS="internal/ebpfcapture/bpf_bpfel.o internal/ebpfcapture/bpf_bpfeb.o"
BINDINGS="internal/ebpfcapture/bpf_bpfel.go internal/ebpfcapture/bpf_bpfeb.go"

refuse() {
	printf 'FAIL: measured nothing, which is not a pass.\n      %s\n' "$1"
	exit 1
}

fail() {
	printf 'FAIL: %s\n' "$1"
	exit 1
}

# ------------------------------------------------- can this even be measured?

command -v "$CC" >/dev/null 2>&1 ||
	refuse "no compiler: \$BPF2GO_CC is '$CC' and it is not on PATH.
      This gate needs clang with the BPF target, llvm-strip, and the
      <bpf/bpf_helpers.h> headers from libbpf-dev. ci.yml's \`ebpf\` job is
      where it runs; Apple's clang has no BPF target, so on macOS use the
      container the job uses."

command -v "$STRIP" >/dev/null 2>&1 ||
	refuse "no '$STRIP' on PATH. bpf2go shells out to it to strip DWARF, so
      without it the comparison would be against a differently-stripped
      object, which is not the same question."

# The whole of --version, not its first line: clang puts the number there
# ("Ubuntu clang version 18.1.3") and llvm-strip does not, opening with
# "llvm-strip, compatible with GNU strip" and carrying "Ubuntu LLVM version
# 18.1.3" on the line below. Reading the first line only returned an empty
# string for the stripper, which compares unequal to every pin and would have
# made this gate fail for a reason it could not explain.
version_of() { "$1" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

cc_version="$(version_of "$CC")"
[ -n "$cc_version" ] ||
	refuse "could not read a version out of '$CC --version', so the compiler
      that would produce the comparison is unknown."

if [ "$cc_version" != "$EXPECTED_CLANG" ]; then
	fail "this repository's committed object was built with clang $EXPECTED_CLANG
      and '$CC' is $cc_version. clang changes its output between versions, so
      comparing across two of them says nothing about the source.

      If the toolchain has moved on purpose, make that one deliberate commit:
        BPF2GO_CC=$CC go generate ./internal/ebpfcapture/...
        # put the 'linux &&' prefix back on both generated .go files
        # set EXPECTED_CLANG=$cc_version in this script
      and say in the commit message which compiler now owns the object."
fi

strip_version="$(version_of "$STRIP")"
[ "$strip_version" = "$EXPECTED_CLANG" ] ||
	fail "'$STRIP' is $strip_version but the compiler is $EXPECTED_CLANG. bpf2go
      strips the compiled object with it, so a mismatched pair produces bytes
      neither toolchain alone would."

for f in $OBJECTS $BINDINGS; do
	[ -f "$f" ] ||
		refuse "$f is not in the tree. There is nothing to compare the source
      against, and a gate whose subject has vanished must say so rather than
      report OK."
done

for f in $BINDINGS; do
	grep -q '^//go:build ' "$f" ||
		refuse "$f has no //go:build line at all. This gate removes that line
      before comparing because bpf2go rewrites it, and it cannot do that to a
      file that does not have one."
done

# ------------------------------------------------------------ compile a copy
#
# A copy, not the working tree: this gate is run beside others and after a
# developer's own edits, and a check that rewrites the files it is judging can
# only be run once.
tmp="$(mktemp -d)" || refuse "could not make a temporary directory."
trap 'rm -rf "$tmp"' EXIT INT TERM

mkdir -p "$tmp/internal/ebpfcapture" || refuse "could not populate the copy."
cp go.mod go.sum "$tmp/" || refuse "could not copy the module files."
cp -R internal/ebpfcapture/. "$tmp/internal/ebpfcapture/" ||
	refuse "could not copy internal/ebpfcapture into the copy."

# The COMMITTED vmlinux.h, deliberately. ci.yml's other eBPF step regenerates it
# from the runner's own BTF and rebuilds, which is a different and also useful
# question (does connect.c still compile against a real current kernel). Mixing
# the two would make this comparison depend on whichever kernel the runner
# happened to boot.
gen_out="$(cd "$tmp" && BPF2GO_CC="$CC" BPF2GO_STRIP="$STRIP" go generate ./internal/ebpfcapture/... 2>&1)"
gen_rc=$?
if [ "$gen_rc" -ne 0 ]; then
	printf 'FAIL: the source did not compile, so nothing was compared.\n'
	printf '%s\n' "$gen_out" | tail -15 | sed 's/^/      /'
	exit 1
fi

for f in $OBJECTS $BINDINGS; do
	[ -f "$tmp/$f" ] ||
		refuse "generation produced no $f. It exited 0 and wrote nothing, which
      would otherwise compare an object against itself."
done

# ------------------------------------------------------------- compare them

differs=0
for f in $OBJECTS; do
	have="$(sha256sum "$f" | cut -d' ' -f1)"
	want="$(sha256sum "$tmp/$f" | cut -d' ' -f1)"
	if [ "$have" = "$want" ]; then
		printf '    ok  %-38s %s\n' "$(basename "$f")" "$have"
	else
		differs=1
		printf '    NO  %s\n        committed  %s\n        compiled   %s\n' "$(basename "$f")" "$have" "$want"
	fi
done

for f in $BINDINGS; do
	# The //go:build line comes off both sides: see the header.
	if grep -v '^//go:build ' "$f" | diff -q - <(grep -v '^//go:build ' "$tmp/$f") >/dev/null 2>&1; then
		printf '    ok  %-38s (bindings match, build line excluded)\n' "$(basename "$f")"
	else
		differs=1
		printf '    NO  %s\n' "$(basename "$f")"
		grep -v '^//go:build ' "$f" | diff -u - <(grep -v '^//go:build ' "$tmp/$f") | head -20 | sed 's/^/        /'
	fi
done

if [ "$differs" -ne 0 ]; then
	printf '\n'
	printf 'The committed object is not what the committed C compiles to.\n'
	printf '\n'
	printf 'Every release binary and published image embeds these bytes, and a\n'
	printf 'pull request shows them as "Binary files differ", so this gate is the\n'
	printf 'only thing between a reviewer and an object nobody derived from the\n'
	printf 'source in front of them.\n'
	printf '\n'
	printf 'Usually this is an honest omission: connect.c was edited and the\n'
	printf 'object was not regenerated. Then, on a machine with the pinned\n'
	printf 'toolchain:\n'
	printf '\n'
	printf '    BPF2GO_CC=%s go generate ./internal/ebpfcapture/...\n' "$CC"
	printf '    # then put the `linux &&` prefix back on both generated .go files,\n'
	printf '    # which bpf2go strips: see the note beside //go:generate in\n'
	printf '    # internal/ebpfcapture/capture_linux.go, and invariant 4.\n'
	printf '\n'
	printf 'If connect.c was NOT edited, do not regenerate. Find out where the\n'
	printf 'object came from.\n'
	exit 1
fi

printf 'OK: both committed objects are byte for byte what %s %s compiles\n' "$CC" "$cc_version"
printf '    connect.c to, from the committed vmlinux.h, and both generated Go\n'
printf '    bindings match apart from the build line ebpf-optional.sh owns.\n'
