//go:build !linux

package main

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
)

func init() {
	ebpfCaptureFunc = func(context.Context, time.Duration) ([]ebpfcapture.Flow, error) {
		return nil, fmt.Errorf("ebpf-capture: not supported on %s (Linux only)", runtime.GOOS)
	}
}
