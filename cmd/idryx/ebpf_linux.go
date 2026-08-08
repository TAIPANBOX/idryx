//go:build linux

package main

import (
	"context"
	"time"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
)

func init() {
	ebpfCaptureFunc = func(ctx context.Context, duration time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		return ebpfcapture.Run(ctx, ebpfcapture.Options{Duration: duration})
	}
}
