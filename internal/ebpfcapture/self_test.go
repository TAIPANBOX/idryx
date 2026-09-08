package ebpfcapture

import "testing"

// Inside a PID namespace the kernel's pid (initial namespace) and os.Getpid()
// (this namespace) never agree, so a self-filter on the raw pid does nothing
// there: measured 2026-09-08, the sensor reported 16 of its own 21 flows from
// a container (TAIPANBOX/idryx#66). The event now carries the tgid as seen
// from the sensor's own namespace, computed by the kernel for tasks in that
// namespace and zero for every other task, and self is decided on that alone.
func TestSelfIsRecognisedByTheNamespacedTGIDNotTheHostPID(t *testing.T) {
	const self = 7
	// The sensor's own connect, seen from a container: host pid 4242, tgid 7 here.
	if !isSelf(decodedConnEvent{pid: 4242, nsTgid: self}, self) {
		t.Error("an event whose namespaced tgid is ours was not recognised as self")
	}
	// A task in another namespace: the kernel reports no namespaced tgid for it.
	// Its host pid may coincide with our namespaced pid, and that is the trap:
	// pid 7 on the host is not us just because we are pid 7 in here.
	if isSelf(decodedConnEvent{pid: self, nsTgid: 0}, self) {
		t.Error("a foreign task whose host pid equals our namespaced pid was mistaken for self")
	}
	// Ordinary traffic from a neighbour in our own namespace.
	if isSelf(decodedConnEvent{pid: 4243, nsTgid: 9}, self) {
		t.Error("a neighbour in our namespace was mistaken for self")
	}
}

// /proc addresses processes by the pid of the namespace that mounted it. On
// the host that is the kernel's pid; inside a container it is the namespaced
// tgid, and a task from another namespace has no address here at all: zero,
// which claimedAgentURI already treats as "not declared".
func TestAClaimIsReadFromThePIDThisNamespaceCanAddress(t *testing.T) {
	ev := decodedConnEvent{pid: 4242, nsTgid: 7}
	if got := procPIDFor(ev, true); got != 4242 {
		t.Errorf("on the host /proc is addressed by the kernel pid: got %d, want 4242", got)
	}
	if got := procPIDFor(ev, false); got != 7 {
		t.Errorf("inside a namespace /proc is addressed by the namespaced tgid: got %d, want 7", got)
	}
	if got := procPIDFor(decodedConnEvent{pid: 4242, nsTgid: 0}, false); got != 0 {
		t.Errorf("a task from another namespace has no /proc address here: got %d, want 0", got)
	}
}
