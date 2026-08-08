package ebpfcapture

import (
	"math"
	"net"
	"strings"
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
	return connEventIn(0, pid, port, family, addr, comm)
}

// putU64 writes one native little-endian 64-bit field.
func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// connEventIn is connEvent with an explicit cgroup id, in connect.c's layout:
// cgroup_id first because it is the only 8-byte field, then pid, port as raw
// network-order bytes, family, one pad byte, 16 address bytes, comm.
func connEventIn(cgroup uint64, pid uint32, port uint16, family uint8, addr []byte, comm string) []byte {
	return connEventAt(cgroup, 0, pid, port, family, addr, comm)
}

// connEventAt is the full record in connect.c's layout: the two 8-byte fields
// first (cgroup, ktime), then pid, port as raw network-order bytes, family, one
// pad byte, 16 address bytes, comm.
func connEventAt(cgroup, ktime uint64, pid uint32, port uint16, family uint8, addr []byte, comm string) []byte {
	b := make([]byte, connEventSize)
	putU64(b[0:8], cgroup)
	putU64(b[8:16], ktime)
	b[16] = byte(pid)
	b[17] = byte(pid >> 8)
	b[18] = byte(pid >> 16)
	b[19] = byte(pid >> 24)
	b[20] = byte(port >> 8) // network byte order: high byte first
	b[21] = byte(port)
	b[22] = family
	copy(b[24:40], addr)
	copy(b[40:56], comm)
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
	const fields = 8 + 8 + 4 + 2 + 1 + 1 + 16 + 16 // cgroup + ktime + pid + dport + family + pad + daddr + comm
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
	got := Identity("python3", 0)
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
		{Time: at, Identity: Identity("curl", 0), Destination: "api.openai.com:443", PID: 7},
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

// The cgroup id is what makes two containers running the same binary two
// identities instead of one. comm alone collapsed them, and a process can
// rewrite its own comm with prctl while it cannot touch its cgroup.
func TestTheCgroupSeparatesTwoContainersRunningTheSameBinary(t *testing.T) {
	one := Identity("python3", 8471)
	two := Identity("python3", 9002)

	if one == two {
		t.Fatalf("two cgroups running python3 collapsed into one identity: %q", one)
	}
	if one != "proc:python3@cg8471" {
		t.Errorf("identity = %q, want proc:python3@cg8471", one)
	}
	// The prefix unmanaged_egress selects on must survive the qualification,
	// or the detector stops seeing these identities and says nothing about it.
	for _, id := range []string{one, two} {
		if !strings.HasPrefix(id, IdentityPrefix) {
			t.Errorf("%q lost the %q prefix the detector selects on", id, IdentityPrefix)
		}
	}
}

// A kernel that gives no cgroup id must produce the identity this package
// produced before cgroups existed here, not "proc:curl@cg0": zero means absent,
// and an absent cgroup rendered as cgroup zero would group every unattributed
// process on such a host into one identity.
func TestAnAbsentCgroupLeavesTheIdentityUnqualified(t *testing.T) {
	if got := Identity("curl", 0); got != "proc:curl" {
		t.Errorf("identity = %q, want proc:curl", got)
	}
}

func TestDecodeReadsTheCgroupFromItsOwnOffset(t *testing.T) {
	raw := connEventIn(8471, 4242, 443, 4, []byte{93, 184, 216, 34}, "python3")

	ev, ok := decodeConnEvent(raw)
	if !ok {
		t.Fatal("a well-formed record must decode")
	}
	if ev.cgroupID != 8471 {
		t.Errorf("cgroupID = %d, want 8471", ev.cgroupID)
	}
	// Everything after it must still land: the cgroup id shifted every other
	// field by eight bytes, and a decoder updated for one field and not the
	// rest reads plausible rubbish rather than failing.
	if ev.pid != 4242 || ev.dport != 443 || ev.family != 4 {
		t.Errorf("fields after the cgroup shifted: pid=%d dport=%d family=%d", ev.pid, ev.dport, ev.family)
	}
	if got := ev.IP().String(); got != "93.184.216.34" {
		t.Errorf("IP = %s, want 93.184.216.34", got)
	}
	if got := trimComm(ev.comm[:]); got != "python3" {
		t.Errorf("comm = %q, want python3", got)
	}
}

// SPEC 3.3: "a value that does not parse MUST be treated as absent rather than
// repaired or truncated". Repairing is the tempting failure here, because the
// sensor has a perfectly good identity to fall back on and inventing a better
// looking one costs nothing at the keyboard.
func TestAnUnusableClaimIsDroppedRatherThanRepaired(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-uri",
		"http://acme.example/bot",
		"agent://",
		"AGENT://ACME.EXAMPLE/BOT", // uppercase: 3.1 says lowercase trust domain
		"agent://acme.example",     // no path segment
	} {
		if got := ClaimedIdentity(bad); got != "" {
			t.Errorf("ClaimedIdentity(%q) = %q, want \"\" so the caller falls back to what it observed", bad, got)
		}
	}
}

func TestAValidClaimIsMarkedAsClaimedRatherThanRecordedAsFact(t *testing.T) {
	const uri = "agent://acme-bank.example/support/tier1-bot"
	got := ClaimedIdentity(uri)

	if got != "claimed:"+uri {
		t.Fatalf("ClaimedIdentity = %q, want it prefixed", got)
	}
	// The prefix is what keeps a self-declared identity distinguishable from
	// one a Passport or an IAM connector established. Without it, SPEC 3.3's
	// "MUST record as claimed" has nowhere to live in this format.
	if !IsClaimed(got) {
		t.Error("IsClaimed says no about an identity this package just marked claimed")
	}
	if IsClaimed(Identity("python3", 8471)) {
		t.Error("an observed identity must not read as claimed")
	}
	if IsClaimed(uri) {
		t.Error("a bare agent:// URI must not read as claimed: that is what a governed connector produces")
	}
}

// The match is on the whole variable name. A prefix or substring match would
// let an unrelated variable name an agent, which is the same class of mistake
// as repairing a malformed URI.
func TestFindEnvMatchesTheWholeVariableName(t *testing.T) {
	environ := []byte("PATH=/usr/bin\x00MY_AGENT_PASSPORT_ID=agent://evil.example/a\x00" +
		"AGENT_PASSPORT_IDX=agent://evil.example/b\x00AGENT_PASSPORT_ID=agent://acme.example/bot\x00")

	if got := findEnv(environ, envVar); got != "agent://acme.example/bot" {
		t.Errorf("findEnv = %q, want the exact variable's value", got)
	}
	if got := findEnv([]byte("PATH=/usr/bin\x00"), envVar); got != "" {
		t.Errorf("findEnv on an environment without it = %q, want empty", got)
	}
	if got := findEnv(nil, envVar); got != "" {
		t.Errorf("findEnv(nil) = %q, want empty", got)
	}
}

// An empty value is present-but-empty, which is not a claim. It must read the
// same as absent rather than producing "claimed:".
func TestAnEmptyClaimIsNotAClaim(t *testing.T) {
	environ := []byte("AGENT_PASSPORT_ID=\x00PATH=/usr/bin\x00")
	if got := ClaimedIdentity(findEnv(environ, envVar)); got != "" {
		t.Errorf("an empty variable produced %q", got)
	}
}

func TestDecodeReadsTheKernelTimestamp(t *testing.T) {
	const ktime = 1_234_567_890_123
	ev, ok := decodeConnEvent(connEventAt(8471, ktime, 4242, 443, 4, []byte{1, 2, 3, 4}, "curl"))
	if !ok {
		t.Fatal("a well-formed record must decode")
	}
	if ev.ktimeNS != ktime {
		t.Errorf("ktimeNS = %d, want %d", ev.ktimeNS, ktime)
	}
	// The timestamp shifted every field after it by eight bytes. A decoder
	// updated for one field and not the rest reads plausible rubbish.
	if ev.cgroupID != 8471 || ev.pid != 4242 || ev.dport != 443 || ev.family != 4 {
		t.Errorf("fields around the timestamp shifted: cgroup=%d pid=%d dport=%d family=%d",
			ev.cgroupID, ev.pid, ev.dport, ev.family)
	}
	if got := trimComm(ev.comm[:]); got != "curl" {
		t.Errorf("comm = %q, want curl", got)
	}
}

// The whole point of carrying a kernel timestamp: the interval between two
// events must come from when the KERNEL saw them, not from when a reader got
// round to them. This pins that two events one second apart in kernel time
// render one second apart, whatever the reader was doing in between.
func TestTheIntervalBetweenTwoEventsSurvivesTheConversion(t *testing.T) {
	start := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	c := clockOffset{wallAtStart: start, monoAtStart: 5_000_000_000}

	first := c.wallTime(5_000_000_000, time.Time{})
	second := c.wallTime(6_000_000_000, time.Time{})

	if !first.Equal(start) {
		t.Errorf("an event at the offset's own instant = %s, want %s", first, start)
	}
	if gap := second.Sub(first); gap != time.Second {
		t.Errorf("interval = %s, want 1s: the kernel saw these one second apart", gap)
	}
}

// A zero timestamp means the kernel gave none. Rendering it through the offset
// would date the flow to the machine's boot: a precise, confident, wrong
// answer, which is the worst kind for a timestamp.
func TestAnAbsentKernelTimestampFallsBackRatherThanDatingToBoot(t *testing.T) {
	c := clockOffset{wallAtStart: time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC), monoAtStart: 5_000_000_000}
	fallback := time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)

	if got := c.wallTime(0, fallback); !got.Equal(fallback) {
		t.Errorf("a zero ktime rendered as %s, want the caller's own clock %s", got, fallback)
	}
	// And with no offset at all (the syscall failed), every event falls back.
	var none clockOffset
	if got := none.wallTime(9_999_999, fallback); !got.Equal(fallback) {
		t.Errorf("with no offset, rendered %s, want %s", got, fallback)
	}
}

// The ring buffer can hold entries written between the program attaching and
// the offset being sampled. Those must keep their order rather than all
// clamping to the start, which would make distinct events look simultaneous.
func TestAnEventFromBeforeTheOffsetKeepsItsOrder(t *testing.T) {
	start := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	c := clockOffset{wallAtStart: start, monoAtStart: 5_000_000_000}

	earlier := c.wallTime(4_000_000_000, time.Time{})
	later := c.wallTime(4_500_000_000, time.Time{})

	if !earlier.Before(later) {
		t.Errorf("two pre-offset events collapsed: %s vs %s", earlier, later)
	}
	if gap := later.Sub(earlier); gap != 500*time.Millisecond {
		t.Errorf("interval = %s, want 500ms", gap)
	}
}

// time.Duration is an int64. A uint64 gap past math.MaxInt64 wraps to a
// negative and renders the event roughly 292 years out, in the wrong direction,
// with nothing complaining. Reaching that needs a 292-year uptime or a corrupt
// record off the ring buffer, and the second is the reachable one.
func TestAnImpossibleGapDoesNotWrapIntoTheDistantPast(t *testing.T) {
	start := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	c := clockOffset{wallAtStart: start, monoAtStart: 1}

	got := c.wallTime(uint64(math.MaxInt64)+2, time.Time{})

	if got.Before(start) {
		t.Errorf("a gap past MaxInt64 rendered %s, before the offset at %s: it wrapped", got, start)
	}
	if !got.Equal(start) {
		t.Errorf("rendered %s, want the offset's own instant %s", got, start)
	}
	// The boundary itself must still convert normally.
	if d := asDuration(uint64(math.MaxInt64)); d != time.Duration(math.MaxInt64) {
		t.Errorf("MaxInt64 itself did not convert: %d", d)
	}
}

// The sub-second part must survive the wire format. RFC3339 has no fractional
// field, so rendering with it rounds every flow to the second: two connections
// 200ms apart become simultaneous, and the jitter a beacon detector measures
// becomes a property of the formatter rather than of the traffic.
func TestTheEgressLogKeepsSubSecondPrecision(t *testing.T) {
	at := time.Date(2026, 8, 9, 12, 30, 0, 200_000_000, time.UTC)
	log := ToEgressLog([]Flow{{Time: at, Identity: Identity("curl", 0), Destination: "x:443"}})

	if log.Flows[0].Time != "2026-08-09T12:30:00.2Z" {
		t.Errorf("time = %q, want the fraction kept", log.Flows[0].Time)
	}
	// And the reader this feeds must accept it: egress.go parses against the
	// RFC3339 layout, which Go matches with or without a fraction.
	back, err := time.Parse(time.RFC3339, log.Flows[0].Time)
	if err != nil {
		t.Fatalf("the egress connector's own parse rejects what we now write: %v", err)
	}
	if !back.Equal(at) {
		t.Errorf("round-tripped to %s, want %s", back, at)
	}
	// A whole second still renders without a trailing dot, so old and new logs
	// look the same where there is nothing to keep.
	whole := ToEgressLog([]Flow{{Time: at.Truncate(time.Second), Identity: "x", Destination: "y:1"}})
	if whole.Flows[0].Time != "2026-08-09T12:30:00Z" {
		t.Errorf("a whole second rendered as %q", whole.Flows[0].Time)
	}
}
