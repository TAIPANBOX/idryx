//go:build linux

package ebpfcapture

import (
	"time"

	"golang.org/x/sys/unix"
)

// newClockOffset samples both clocks once, as close together as one goroutine
// can manage, so kernel timestamps can be rendered as wall-clock time.
//
// CLOCK_MONOTONIC because that is what bpf_ktime_get_ns() reads. Asking for
// anything else here would produce an offset that looks right and drifts: the
// two clocks tick at the same rate but start from different origins, so a
// mismatched pair is wrong by a constant nobody would notice until they
// compared a flow against another host's log.
//
// A failed read returns a zero offset, which wallTime treats as "no mapping"
// and falls back to the caller's own clock. That is the honest degradation:
// the capture still works and its timestamps are merely as good as they were
// before this file existed.
func newClockOffset() clockOffset {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return clockOffset{}
	}
	// Wall clock read second and immediately: the gap between these two lines
	// is the error in the offset, and it is the reason they are adjacent with
	// nothing between them.
	wall := time.Now()
	mono := uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec) // #nosec G115 -- both fields are non-negative for CLOCK_MONOTONIC
	return clockOffset{wallAtStart: wall, monoAtStart: mono}
}
