package ebpfcapture

import (
	"net"
	"testing"
	"time"
)

// This file is the package's first test. Until 2026-08-08 `go test ./...`
// reported `internal/ebpfcapture  [no test files]` for the sensor the estate
// has just made its primary one (AGENTS.md invariant 7), while the only thing
// exercising any of it was the unmanaged_egress detector, one layer up and
// through a hand-built graph.
//
// Everything here runs on every platform on purpose. The decoder, the address
// rendering and the skipped counters are the parts with no kernel in them,
// which is exactly why connect.c hands them raw bytes and lets Go resolve byte
// order (see connect.c's own comment). A wire format tested only where it can
// be captured is tested only where somebody happens to have root.

// connEvent builds one 40-byte record in connect.c's layout: pid native, port
// as raw network-order bytes, family, one pad byte, 16 address bytes, comm
// NUL-padded.
func connEvent(pid uint32, port uint16, family uint8, addr []byte, comm string) []byte {
	b := make([]byte, connEventSize)
	b[0] = byte(pid)
	b[1] = byte(pid >> 8)
	b[2] = byte(pid >> 16)
	b[3] = byte(pid >> 24)
	b[4] = byte(port >> 8) // network byte order: high byte first
	b[5] = byte(port)
	b[6] = family
	copy(b[8:24], addr)
	copy(b[24:40], comm)
	return b
}

func TestDecodeConnEventReadsEachFieldFromItsOwnOffset(t *testing.T) {
	raw := connEvent(4242, 443, 4, []byte{93, 184, 216, 34}, "curl")

	ev, ok := decodeConnEvent(raw)
	if !ok {
		t.Fatal("a well-formed record must decode")
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
	if ev.family != 4 {
		t.Errorf("family = %d, want 4", ev.family)
	}
	if got := ev.IP().String(); got != "93.184.216.34" {
		t.Errorf("IP = %s, want 93.184.216.34", got)
	}
	if got := trimComm(ev.comm[:]); got != "curl" {
		t.Errorf("comm = %q, want %q", got, "curl")
	}
}

func TestDecodeConnEventReadsAnIPv6Address(t *testing.T) {
	addr := net.ParseIP("2606:4700:4700::1111").To16()
	raw := connEvent(9, 443, 6, addr, "python3")

	ev, ok := decodeConnEvent(raw)
	if !ok {
		t.Fatal("an IPv6 record must decode")
	}
	if ev.family != 6 {
		t.Fatalf("family = %d, want 6", ev.family)
	}
	if got := ev.IP().String(); got != "2606:4700:4700::1111" {
		t.Errorf("IP = %s, want 2606:4700:4700::1111", got)
	}
}

// The family byte is not decoration: without it, a 4-byte IPv4 address written
// into a zeroed 16-byte field and a real IPv6 address in ::ffff:0.0.0.0/96 are
// the same bytes, and one of the two would be reported as the other.
func TestTheFamilyByteDecidesHowTheAddressIsRead(t *testing.T) {
	addr := make([]byte, 16)
	copy(addr, []byte{10, 0, 0, 1})

	asV4, _ := decodeConnEvent(connEvent(1, 443, 4, addr, "x"))
	asV6, _ := decodeConnEvent(connEvent(1, 443, 6, addr, "x"))

	if got := asV4.IP().String(); got != "10.0.0.1" {
		t.Errorf("family 4: IP = %s, want 10.0.0.1", got)
	}
	if got := asV6.IP().String(); got != "a00:1::" {
		t.Errorf("family 6: IP = %s, want a00:1:: (the same bytes, read as IPv6)", got)
	}
}

// connect.c only ever writes 4 or 6. Anything else means the record's layout is
// not the one this decoder was written against, so IP() returns nil and the
// caller skips it: reporting an address off a layout we do not recognise would
// be worse than reporting nothing.
func TestAnUnknownFamilyHasNoAddressRatherThanAWrongOne(t *testing.T) {
	for _, family := range []uint8{0, 2, 10, 255} {
		ev, ok := decodeConnEvent(connEvent(1, 443, family, []byte{1, 2, 3, 4}, "x"))
		if !ok {
			t.Fatalf("family %d: a full-length record must still decode", family)
		}
		if ip := ev.IP(); ip != nil {
			t.Errorf("family %d: IP = %s, want nil", family, ip)
		}
	}
}

// A record shorter than the struct is a mismatched connect.c/decode.go pair or
// a corrupt ring buffer entry. It must be refused rather than misread off a
// shifted layout, and refusing is what lets Run skip it instead of panicking a
// live capture.
func TestDecodeConnEventRefusesAShortRecord(t *testing.T) {
	full := connEvent(1, 443, 4, []byte{1, 2, 3, 4}, "x")
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
// decoder actually indexes with.
func TestConnEventSizeMatchesTheOffsetsTheDecoderUses(t *testing.T) {
	const fields = 4 + 2 + 1 + 1 + 16 + 16 // pid + dport + family + pad + daddr + comm
	if connEventSize != fields {
		t.Errorf("connEventSize = %d, but the fields the decoder reads span %d bytes", connEventSize, fields)
	}
}

// An IPv6 destination has colons in it, and every consumer downstream splits a
// destination on the last colon to separate host from port. Without brackets,
// "2001:db8::1" and port 443 render as a string nothing can parse back, and the
// failure is silent: the egress connector accepts it, normalizeHost trims the
// wrong piece, and matchLLM compares against a host that never existed.
func TestAnIPv6DestinationIsBracketedSoItCanBeParsedBack(t *testing.T) {
	got := destination(net.ParseIP("2606:4700:4700::1111"), 443, nil)
	if got != "[2606:4700:4700::1111]:443" {
		t.Fatalf("destination = %q, want it bracketed", got)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("the rendered destination does not parse back: %v", err)
	}
	if host != "2606:4700:4700::1111" || port != "443" {
		t.Errorf("parsed back as %q/%q", host, port)
	}
}

func TestAKnownLLMAddressIsRenderedUnderItsHostname(t *testing.T) {
	llm := map[string]string{"2606:4700:4700::1111": "api.openai.com", "1.2.3.4": "api.anthropic.com"}

	if got := destination(net.ParseIP("1.2.3.4"), 443, llm); got != "api.anthropic.com:443" {
		t.Errorf("IPv4 = %q, want api.anthropic.com:443", got)
	}
	if got := destination(net.ParseIP("2606:4700:4700::1111"), 443, llm); got != "api.openai.com:443" {
		t.Errorf("IPv6 = %q, want api.openai.com:443", got)
	}
	// An unresolved address keeps its own form, brackets and all.
	if got := destination(net.ParseIP("2001:db8::99"), 8443, llm); got != "[2001:db8::99]:8443" {
		t.Errorf("unresolved IPv6 = %q", got)
	}
}

func TestLocalModelPortsAreOneListForFilterAndClassifier(t *testing.T) {
	for _, p := range []uint16{11434, 8000, 8001} {
		if !isLocalModelPort(p) {
			t.Errorf("port %d is a local model port and must survive the loopback filter", p)
		}
	}
	for _, p := range []uint16{0, 22, 443, 5432} {
		if isLocalModelPort(p) {
			t.Errorf("port %d is ordinary loopback chatter and must be dropped", p)
		}
	}
}

// Zero flows has three meanings without these counters, which is the whole
// reason connect.c maintains them: nothing connected, everything connected over
// a family this sensor ignores, or the ring buffer filled and real evidence was
// lost. Any() and Lost() are what let a caller tell the third from the first two.
func TestSkippedDistinguishesOutOfScopeTrafficFromLostEvidence(t *testing.T) {
	var clean SkippedCounts
	if clean.Any() || clean.Lost() {
		t.Error("a clean capture must report neither")
	}

	outOfScope := SkippedCounts{OtherFamily: 4096, Unreadable: 3}
	if !outOfScope.Any() {
		t.Error("out-of-scope traffic is worth reporting")
	}
	if outOfScope.Lost() {
		t.Error("out-of-scope traffic is not lost evidence; a busy host makes AF_UNIX connections constantly")
	}

	lost := SkippedCounts{RingbufFull: 1}
	if !lost.Any() || !lost.Lost() {
		t.Error("one dropped connection means the capture is incomplete and must say so")
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
