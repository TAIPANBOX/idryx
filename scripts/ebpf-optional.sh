#!/usr/bin/env bash
# Enforces invariant 4 of AGENTS.md: the eBPF layer is optional and Linux-only,
# and its absence is a reported fact rather than a silent skip.
#
# Three halves, and they fail in different ways.
#
#   1. idryx BUILDS where eBPF does not exist. Checked by cross-compiling the
#      whole tree for darwin and windows, on both amd64 and arm64. The second
#      dimension is not thoroughness: the sensor's bindings are per-architecture
#      since 2026-09-09, so a check using only the host's GOARCH cannot see a
#      file for the other one losing its OS constraint.
#
#   2. The eBPF dependency is genuinely ABSENT off Linux, not merely harmless.
#      `go list -deps` for darwin and windows must contain zero cilium/ebpf
#      packages, and for linux must contain them. Building is a weaker claim
#      than not depending: until 2026-08-01 the tree cross-compiled fine while
#      dragging all 19 cilium/ebpf packages into a windows build that can never
#      use them, because bpf2go tags its output by ARCHITECTURE with no OS
#      constraint. This is the half that keeps the `linux &&` in front of those
#      tags, which a regeneration will silently remove.
#
#   3. The absence is REPORTED. cmd/idryx/ebpf_other.go carries `//go:build
#      !linux` and every path through its capture entry point must return an
#      error naming the platform. A stub that returns an empty result and no
#      error is the exact failure invariant 4 exists to prevent: a partial
#      graph presented as a complete one.
#
# WHAT THIS CHECK DOES NOT DO, SAID OUT LOUD RATHER THAN SKIPPED. Half 2 has a
# behavioural form (run `idryx ebpf-capture` and read what it says) that only
# works on a machine that is not Linux. On a Linux host the check proves the
# structural half and says so. A check that quietly proves less on some hosts
# than on others, without saying which it did, is the same class of thing as
# the silent skip this invariant forbids.
#
# WHAT REPLACED sandbox.mod, AND WHY. Invariant 6 used to say sandbox.mod
# "exists to prove the core builds without the eBPF dependency" and "is not a
# scratch file". Measured 2026-08-01, all three claims were false: it was never
# in the repository (excluded through .git/info/exclude, which is per-clone and
# never travels), it did not build, and it excluded agent-stack-go, which
# invariant 3 says is the ONLY source of the wire types and therefore never
# optional. It was measuring the wrong boundary.
#
# Part 2 measures the right one, per GOOS, from files that are committed, with
# no second module file for anyone to keep in step by hand.
#
# This file is the ONE copy of this check.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0
note() {
  printf 'FAIL: %s\n' "$1"
  fail=1
}

# ------------------------------------------------------------ 1. it builds
#
# Both architectures, not just the host's. The sensor's generated bindings are
# per-architecture since 2026-09-09, so a file that lost its OS constraint is
# invisible to a check that only ever cross-compiles for whatever GOARCH the
# machine running it happens to have. That is not hypothetical: it made this
# gate's own teeth case report TOOTHLESS the moment the objects were split,
# on an arm64 laptop, while the same case would have passed on an amd64 runner.
for os in darwin windows; do
  for arch in amd64 arm64; do
    if ! out=$(GOOS="$os" GOARCH="$arch" go build ./... 2>&1); then
      note "the tree does not build for GOOS=$os GOARCH=$arch, so idryx cannot run on a
      machine without eBPF. Usually this is a Linux-only import in a file with
      no OS build tag.
$(printf '%s' "$out" | sed 's/^/      /' | head -12)"
    fi
  done
done

# ------------------------------------------- 2. the dependency is really absent
#
# Building is a weaker claim than not depending. Ask the dependency graph
# directly, per GOOS. The linux side is checked too: an allow-list with nothing
# on the other side of it would pass while the capture no longer worked at all.
for os in darwin windows; do
  for arch in amd64 arm64; do
    n=$(GOOS="$os" GOARCH="$arch" go list -deps ./... 2>/dev/null | grep -c 'cilium/ebpf')
    if [ "$n" -ne 0 ]; then
      note "a GOOS=$os GOARCH=$arch build pulls in $n cilium/ebpf packages, which it can
      never use. Almost always this is bpf2go output that lost its \`linux &&\`
      prefix: bpf2go tags by architecture only and has no flag for an OS
      constraint, so a regeneration removes it silently. See the note beside
      //go:generate in internal/ebpfcapture/capture_linux.go."
    fi
  done
done

n_linux=$(GOOS=linux go list -deps ./... 2>/dev/null | grep -c 'cilium/ebpf')
if [ "$n_linux" -eq 0 ]; then
  note "a GOOS=linux build pulls in NO cilium/ebpf packages, so the capture that
      this whole invariant is about is not being compiled anywhere. The other
      half of this check would pass happily on a tree with no eBPF at all."
fi

# --------------------------------------------------- 3. the absence is reported
STUB=cmd/idryx/ebpf_other.go
if [ ! -f "$STUB" ]; then
  note "$STUB is gone. It is the whole of 'the absence is a reported fact': without
      it there is no non-Linux path to report anything."
else
  if ! head -3 "$STUB" | grep -q '^//go:build !linux'; then
    note "$STUB has lost its '//go:build !linux' tag, so the non-Linux report is
      either compiled everywhere or nowhere."
  fi
  if ! grep -q 'runtime.GOOS' "$STUB"; then
    note "$STUB no longer names the platform it is refusing on. 'not supported' with
      no platform makes an operator guess which machine is wrong."
  fi
  # Every return in the stub must carry a non-nil error. `return nil, nil` or a
  # bare `return nil` is a silent skip wearing a stub's clothes.
  if grep -nE '^\s*return\s+(nil,\s*nil|nil)\s*$' "$STUB" >/dev/null; then
    note "$STUB has a return path with no error:
$(grep -nE '^\s*return\s+(nil,\s*nil|nil)\s*$' "$STUB" | sed 's/^/      /')
      A stub that returns success on a machine that cannot observe anything
      presents a partial graph as a complete one, which is what invariant 4 is
      about."
  fi
fi

# ------------------------- 4. the object claims only what it was compiled for
#
# bpf2go groups 386 with amd64 under one target and emits `//go:build 386 ||
# amd64`. The object is not both. bpf_tracing.h picks its register names inside
# `#if defined(__KERNEL__) || defined(__VMLINUX_H__)`, which is the branch this
# program takes, and that branch is x86_64's: di, si, dx, cx. The i386 branch
# below it is unreachable here, so an object tagged 386 would read the wrong
# registers on a 32-bit kernel, silently.
#
# That is the exact defect this estate corrected in tokenfuse's radar on
# 2026-09-09: one object claiming an architecture whose register layout it does
# not use. The narrowing is a hand edit on generated output, so a regeneration
# removes it, which is why it is checked here beside the `linux &&` one.
for f in internal/ebpfcapture/bpf_*.go; do
  [ -f "$f" ] || continue
  if grep -q '^//go:build .*\b386\b' "$f"; then
    note "$f claims GOARCH 386. bpf2go groups 386 with amd64, but the object is
      compiled with x86_64's register names (bpf_tracing.h takes its
      __VMLINUX_H__ branch, di/si/dx/cx), so on a 32-bit kernel it would read
      the wrong registers and report plausible, wrong addresses. Narrow the tag
      to amd64, as the note beside //go:generate in capture_linux.go says."
  fi
done

n_objects=$(ls internal/ebpfcapture/bpf_*.o 2>/dev/null | wc -l | tr -d ' ')
if [ "$n_objects" -eq 0 ]; then
  note "there is no compiled BPF object in internal/ebpfcapture at all, so the
      checks above measured nothing about what ships. The sensor embeds these
      with //go:embed; without them there is no sensor."
fi

# ------------------------------------- the behavioural half, where it is possible
host_os=$(go env GOOS)
if [ "$host_os" = "linux" ]; then
  echo "    (host is Linux, so the structural half is what ran; the message itself"
  echo "     can only be read on a non-Linux machine)"
else
  out=$(go run ./cmd/idryx ebpf-capture 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    note "on $host_os, which has no eBPF, 'idryx ebpf-capture' exited 0. A command
      that cannot do its job must fail, not return success quietly."
  elif ! printf '%s' "$out" | grep -q "$host_os"; then
    note "on $host_os, 'idryx ebpf-capture' failed but did not name the platform:
$(printf '%s' "$out" | sed 's/^/      /' | tail -3)"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "idryx must run and produce a graph on a machine with no eBPF, and must say"
  echo "what it could not observe. See AGENTS.md invariant 4."
  exit 1
fi

echo "OK: the tree cross-compiles for darwin and windows and pulls in zero"
echo "    cilium/ebpf packages there ($n_linux on linux, where it is used);"
echo "    the non-Linux path reports the missing capability and fails rather than"
echo "    returning a partial graph as a complete one."
