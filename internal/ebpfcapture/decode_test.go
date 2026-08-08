package ebpfcapture

import (
	"testing"
	"time"
)

// This file is the package's first test. Until 2026-08-08 `go test ./...`
// reported `internal/ebpfcapture  [no test files]` for the sensor the estate
// has just made its primary one (AGENTS.md invariant 7), while the only thing
// exercising any of it was the unmanaged_egress detector, one layer up and
// through a hand-built graph.
//
// Everything here runs on every platform on purpose. decodeConnEvent, Identity
// and ToEgressLog are the parts with no kernel in them, which is exactly why
// connect.c hands them raw bytes and lets Go resolve byte order (see connect.c's
// own comment). A wire format tested only where it can be captured is tested
// only where somebody happens to have root.

// connEvent builds one 28-byte record in connect.c's layout: pid native, port
// and address as raw network-order bytes, comm NUL-padded, two bytes of
// trailing pad.
func connEvent(pid uint32, port uint16, addr [4]byte, comm string) []byte {
	b := make([]byte, connEventSize)
	b[0] = byte(pid)
	b[1] = byte(pid >> 8)
	b[2] = byte(pid >> 16)
	b[3] = byte(pid >> 24)
	b[4] = byte(port >> 8) // network byte order: high byte first
	b[5] = byte(port)
	copy(b[6:10], addr[:])
	copy(b[10:26], comm)
	return b
}

func TestDecodeConnEventReadsEachFieldFromItsOwnOffset(t *testing.T) {
	raw := connEvent(4242, 443, [4]byte{93, 184, 216, 34}, "curl")

	ev, ok := decodeConnEvent(raw)
	if !ok {
		t.Fatal("a well-formed 28-byte record must decode")
	}
	if ev.pid != 4242 {
		t.Errorf("pid = %d, want 4242", ev.pid)
	}
	// The one that would survive a byte-order mistake unnoticed in the other
	// direction: 443 big-endian read as little-endian is 47873, a plausible
	// ephemeral port rather than an obvious wrong answer.
	if ev.dport != 443 {
		t.Errorf("dport = %d, want 443 (read as network byte order, not host)", ev.dport)
	}
	if ev.daddr != [4]byte{93, 184, 216, 34} {
		t.Errorf("daddr = %v, want 93.184.216.34 octet for octet", ev.daddr)
	}
	if got := trimComm(ev.comm[:]); got != "curl" {
		t.Errorf("comm = %q, want %q", got, "curl")
	}
}

// A record shorter than the struct is a mismatched connect.c/Go pair or a
// corrupt ring buffer entry. It must be refused rather than misread off a
// shifted layout, and refusing is what lets Run skip it instead of panicking a
// live capture.
func TestDecodeConnEventRefusesAShortRecord(t *testing.T) {
	full := connEvent(1, 443, [4]byte{1, 2, 3, 4}, "x")
	for _, n := range []int{0, 1, connEventSize - 1} {
		if _, ok := decodeConnEvent(full[:n]); ok {
			t.Errorf("a %d-byte record decoded; only %d bytes or more can", n, connEventSize)
		}
	}
	if _, ok := decodeConnEvent(full); !ok {
		t.Errorf("exactly %d bytes must decode; the boundary is inclusive", connEventSize)
	}
}

// connEventSize is a hand-maintained mirror of sizeof(struct conn_event) in
// connect.c. Nothing compiles the two together, so this pins the number the
// decoder actually indexes with: the last field it reads ends at byte 26 and
// two bytes of declared padding follow.
func TestConnEventSizeMatchesTheOffsetsTheDecoderUses(t *testing.T) {
	const lastFieldEnds = 4 + 2 + 4 + 16 // pid + dport + daddr + comm
	const declaredPad = 2
	if connEventSize != lastFieldEnds+declaredPad {
		t.Errorf("connEventSize = %d, but the fields the decoder reads end at %d with %d bytes of pad declared in connect.c",
			connEventSize, lastFieldEnds, declaredPad)
	}
}

func TestIdentityIsPrefixedSoTheDetectorCanRecognizeIt(t *testing.T) {
	got := Identity("python3")
	if got != "proc:python3" {
		t.Errorf("Identity(python3) = %q, want proc:python3", got)
	}
	// unmanaged_egress selects on exactly this prefix; the two must not drift.
	if len(got) <= len(IdentityPrefix) || got[:len(IdentityPrefix)] != IdentityPrefix {
		t.Errorf("Identity output %q does not carry IdentityPrefix %q", got, IdentityPrefix)
	}
}

func TestToEgressLogProducesTheShapeTheEgressConnectorParses(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 30, 0, 0, time.UTC)
	log := ToEgressLog([]Flow{
		{Time: at, Identity: Identity("curl"), Destination: "api.openai.com:443", PID: 7},
	})

	if len(log.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(log.Flows))
	}
	f := log.Flows[0]
	if f.Time != "2026-08-08T12:30:00Z" {
		t.Errorf("time = %q, want RFC3339 in UTC", f.Time)
	}
	if f.Identity != "proc:curl" || f.Destination != "api.openai.com:443" {
		t.Errorf("identity/destination = %q/%q", f.Identity, f.Destination)
	}
	// Zero is a fact about sys_enter_connect, not an unfilled field: the
	// tracepoint fires before any data moves. Pinned so that a later sensor
	// that CAN count bytes has to change this test deliberately.
	if f.Bytes != 0 {
		t.Errorf("bytes = %d, want 0: sys_enter_connect fires before any transfer", f.Bytes)
	}
}

// An empty capture must still produce a parseable document with an empty list,
// never a null, or `idryx detect --load egress:<file>` fails on a run that
// simply observed nothing.
func TestToEgressLogOnNoFlowsIsAnEmptyListNotNull(t *testing.T) {
	log := ToEgressLog(nil)
	if log.Flows == nil {
		t.Error("Flows is nil, which marshals to null; want an empty list")
	}
	if len(log.Flows) != 0 {
		t.Errorf("flows = %d, want 0", len(log.Flows))
	}
}

func trimComm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
