package ebpfcapture

import "time"

// This file has no build tag: turning a kernel monotonic reading into a wall
// clock time is arithmetic, and arithmetic is testable without a kernel. The
// one call that asks Linux what time it is lives in clock_linux.go.

// clockOffset converts the kernel's CLOCK_MONOTONIC nanoseconds, which is what
// bpf_ktime_get_ns() returns, into wall-clock time.
//
// **Why the conversion exists at all.** The egress wire shape carries an
// RFC3339 timestamp (see flow.go), so a monotonic counter cannot travel in it:
// nanoseconds since some boot mean nothing to a reader, to another host, or to
// the same host tomorrow. But the monotonic reading is the accurate one, taken
// inside the syscall, while a userspace stamp is taken after ring-buffer
// buffering and after the Go scheduler got round to this goroutine. So the
// accurate measurement is taken from the kernel and expressed in the format the
// format requires, rather than choosing between them.
//
// **Why one pair of readings and not a call per event.** Sampling both clocks
// once, at the start of a capture, costs one syscall for the whole run and
// keeps every flow on one consistent mapping. Sampling per event would drift
// against itself: two events a microsecond apart could land under different
// offsets, and the interval between them, the thing this exists to measure,
// would be an artefact of when the reader looked rather than of when the
// connections happened.
//
// **What it inherits.** CLOCK_MONOTONIC does not advance while the machine is
// suspended, so a laptop that slept for an hour mid-capture will render later
// events an hour early. That is a real limit and it is why this is not used for
// anything but ordering and intervals within one capture; the wall clock a
// human reads is still fundamentally the wall clock this offset was built from.
type clockOffset struct {
	wallAtStart time.Time
	monoAtStart uint64
}

// wallTime renders one kernel timestamp as wall-clock UTC.
//
// A zero ktime means the kernel gave none, and then the answer is the caller's
// own clock rather than an invented one: rendering zero through the offset
// would date every such flow to the moment the machine booted, which is a
// confident, precise, wrong answer, and the worst kind for a timestamp.
func (c clockOffset) wallTime(ktimeNS uint64, fallback time.Time) time.Time {
	if ktimeNS == 0 || c.monoAtStart == 0 {
		return fallback.UTC()
	}
	if ktimeNS >= c.monoAtStart {
		return c.wallAtStart.Add(time.Duration(ktimeNS - c.monoAtStart)).UTC()
	}
	// An event stamped before this capture started: the ring buffer can hold
	// entries written between the program attaching and the offset being taken.
	// Subtracting keeps them in order rather than clamping them all to the
	// start, which would make several distinct events look simultaneous.
	return c.wallAtStart.Add(-time.Duration(c.monoAtStart - ktimeNS)).UTC()
}
