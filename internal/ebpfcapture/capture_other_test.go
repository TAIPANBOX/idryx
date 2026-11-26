//go:build !linux

package ebpfcapture

import "testing"

// TestUnprivilegedSensorParts has its body in capture_linux_test.go: the sensor
// is Linux-only. Declared here too so the module has the same test functions on
// every platform, which is what the README's tests badge counts.
func TestUnprivilegedSensorParts(t *testing.T) {
	t.Skip("the eBPF sensor is Linux-only")
}
