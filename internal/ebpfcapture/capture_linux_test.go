//go:build linux

package ebpfcapture

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunRefusesWithoutPrivilegeBeforeTouchingTheKernel: an unprivileged run
// is a clear error and no flows, not an empty capture that reads as a quiet
// host (AGENTS.md invariant 4).
func testRunRefusesWithoutPrivilegeBeforeTouchingTheKernel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the refusal under test does not apply")
	}
	flows, skipped, err := Run(context.Background(), Options{Duration: time.Millisecond})
	if err == nil {
		t.Fatal("an unprivileged capture reported success")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Errorf("error = %v, want it to say root (or CAP_BPF+CAP_PERFMON) is required", err)
	}
	if flows != nil || skipped.Any() {
		t.Errorf("a refused capture returned flows %v / skipped %+v", flows, skipped)
	}
}

// TestTheCommittedObjectCarriesWhatRunSets checks, without loading anything
// into a kernel, that the embedded object has the program, maps and the two
// namespace variables Run writes before it loads. Run can only discover a
// mismatch as root; this finds it in an unprivileged test.
func testTheCommittedObjectCarriesWhatRunSets(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("the embedded object does not parse: %v", err)
	}
	for _, v := range []string{"self_pidns_dev", "self_pidns_ino"} {
		if _, ok := spec.Variables[v]; !ok {
			t.Errorf("variable %s missing from the object", v)
		}
	}
	if _, ok := spec.Programs["on_connect"]; !ok {
		t.Error("program on_connect missing from the object")
	}
	for _, m := range []string{"events", "skipped"} {
		if _, ok := spec.Maps[m]; !ok {
			t.Errorf("map %s missing from the object", m)
		}
	}
}

// TestClaimedAgentURIReadsTheLiveProcessItWasGiven reads a real child's
// environment: its declared id when it has one, nothing when it has none,
// and nothing once it has exited (SPEC 3.3: a failed read is "not declared").
func testClaimedAgentURIReadsTheLiveProcessItWasGiven(t *testing.T) {
	start := func(env ...string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command("sleep", "30")
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			t.Skipf("cannot start a child process: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}

	declared := start("PATH=/usr/bin:/bin", envVar+"=agent://acme.example/planner")
	if got := claimedAgentURI(uint32(declared.Process.Pid)); got != "agent://acme.example/planner" {
		t.Errorf("declared child: claimedAgentURI = %q, want agent://acme.example/planner", got)
	}

	silent := start("PATH=/usr/bin:/bin")
	if got := claimedAgentURI(uint32(silent.Process.Pid)); got != "" {
		t.Errorf("child with no declaration: claimedAgentURI = %q, want empty", got)
	}

	gone := start(envVar + "=agent://acme.example/gone")
	pid := uint32(gone.Process.Pid)
	_ = gone.Process.Kill()
	_ = gone.Wait()
	if got := claimedAgentURI(pid); got != "" {
		t.Errorf("exited child: claimedAgentURI = %q, want empty", got)
	}

	if got := claimedAgentURI(0); got != "" {
		t.Errorf("pid 0: claimedAgentURI = %q, want empty", got)
	}
}

// TestNewClockOffsetMapsTheKernelClockOntoNow: an offset taken now renders
// its own monotonic instant as roughly now, so kernel timestamps land on the
// wall clock instead of on the boot time.
func testNewClockOffsetMapsTheKernelClockOntoNow(t *testing.T) {
	before := time.Now()
	off := newClockOffset()
	after := time.Now()
	if off.monoAtStart == 0 {
		t.Fatal("CLOCK_MONOTONIC read as zero, so no mapping was taken")
	}
	if off.wallAtStart.Before(before) || off.wallAtStart.After(after) {
		t.Errorf("wall clock %s taken outside [%s, %s]", off.wallAtStart, before, after)
	}
	fallback := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	got := off.wallTime(off.monoAtStart+uint64(time.Second), fallback)
	if d := got.Sub(off.wallAtStart); d != time.Second {
		t.Errorf("one second after the offset renders %s after it, want 1s", d)
	}
}

// TestResolveLLMHostsKeepsWhatResolvesAndSkipsWhatDoesNot uses names that
// need no network: localhost from the hosts file and a reserved .invalid
// name that never resolves.
func testResolveLLMHostsKeepsWhatResolvesAndSkipsWhatDoesNot(t *testing.T) {
	got := resolveLLMHosts([]string{"localhost", "idryx-test.invalid"})
	if len(got) == 0 {
		t.Fatal("localhost resolved to nothing")
	}
	for ip, host := range got {
		if host != "localhost" {
			t.Errorf("%s mapped to %q; only localhost resolves here", ip, host)
		}
	}
}

// TestUnprivilegedSensorParts is one test function on every platform (see
// capture_other_test.go), so the README's count of test functions is the same
// wherever it is taken; the parts themselves exist only on Linux.
func TestUnprivilegedSensorParts(t *testing.T) {
	t.Run("RunRefusesWithoutPrivilegeBeforeTouchingTheKernel", testRunRefusesWithoutPrivilegeBeforeTouchingTheKernel)
	t.Run("TheCommittedObjectCarriesWhatRunSets", testTheCommittedObjectCarriesWhatRunSets)
	t.Run("ClaimedAgentURIReadsTheLiveProcessItWasGiven", testClaimedAgentURIReadsTheLiveProcessItWasGiven)
	t.Run("NewClockOffsetMapsTheKernelClockOntoNow", testNewClockOffsetMapsTheKernelClockOntoNow)
	t.Run("ResolveLLMHostsKeepsWhatResolvesAndSkipsWhatDoesNot", testResolveLLMHostsKeepsWhatResolvesAndSkipsWhatDoesNot)
}
