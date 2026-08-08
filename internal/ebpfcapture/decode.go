package ebpfcapture

import (
	"encoding/binary"
	"net"
)

// This file has no build tag, and that is the point of it existing.
//
// connect.c deliberately copies the port and address to userspace as RAW
// network-order bytes and converts nothing, so that "the one place that has to
// reason about byte order is Go, where it is easy to unit test, not C, where it
// is not" -- its own words. That intent was only half true while the decoder
// lived in capture_linux.go behind `//go:build linux`: easy to unit test, on a
// Linux machine, which is not where most of this repository is written or where
// `go test ./...` usually runs. The decoder needs no kernel, no root and no
// cilium/ebpf, only the layout, so it belongs beside flow.go and identity.go
// with the rest of the platform-independent shape.
//
// AGENTS.md invariant 4 is unaffected and was re-checked after the move: this
// file imports encoding/binary and net, and no cilium/ebpf package, so a darwin
// or windows build still pulls in zero of them.

// connEventSize is sizeof(struct conn_event) in connect.c: 8 (cgroup_id) +
// 8 (ktime_ns) + 4 (pid) + 2 (dport) + 1 (family) + 1 (pad) + 16 (daddr) +
// 16 (comm) = 56 bytes. decodeConnEvent refuses anything shorter, so a future connect.c
// change that isn't mirrored here fails loudly (a skipped record, counted by
// the caller) rather than silently misreading a shifted layout.
//
// It was 28 while the sensor was AF_INET-only, 40 when the address field became
// 16 bytes for both families, 48 with the cgroup id, and 56 with the kernel
// timestamp. The two 8-byte fields lead the struct because anywhere else they
// force padding the two sides have to agree about implicitly.
const connEventSize = 56

// decodedConnEvent is conn_event's already-byte-order-resolved form: dport and
// daddr converted out of connect.c's deliberately-raw wire bytes (see
// connect.c's own doc comment for why that conversion happens here, not in the
// eBPF program).
//
// daddr stays a fixed 16 bytes exactly as it arrives. Family says how many of
// them mean anything, and IP() is the one place that decides: without the
// explicit family, a real IPv6 address in ::ffff:0.0.0.0/96 and a 4-byte IPv4
// write into a zeroed 16-byte field are the same bytes.
type decodedConnEvent struct {
	cgroupID uint64
	ktimeNS  uint64
	pid      uint32
	dport    uint16
	family   uint8
	daddr    [16]byte
	comm     [16]byte
}

// IP returns the destination address, or nil if the record carries a family
// this build does not know. nil is a decode failure the caller must skip, never
// an address to report: an unknown family means the record's layout is not the
// one this decoder was written against.
func (e decodedConnEvent) IP() net.IP {
	switch e.family {
	case 4:
		return net.IPv4(e.daddr[0], e.daddr[1], e.daddr[2], e.daddr[3])
	case 6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, e.daddr[:])
		return ip
	default:
		return nil
	}
}

// decodeConnEvent parses one ring buffer record against connect.c's struct
// conn_event layout exactly (see connEventSize). false means the record is the
// wrong size -- a mismatched connect.c/decode.go pair, or ring buffer
// corruption -- and is skipped rather than panicking a live capture over one
// bad record.
func decodeConnEvent(raw []byte) (decodedConnEvent, bool) {
	if len(raw) < connEventSize {
		return decodedConnEvent{}, false
	}
	var ev decodedConnEvent
	ev.cgroupID = binary.LittleEndian.Uint64(raw[0:8]) // native byte order, kernel-assigned, never crosses the network
	ev.ktimeNS = binary.LittleEndian.Uint64(raw[8:16]) // CLOCK_MONOTONIC nanoseconds, the kernel's own clock
	ev.pid = binary.LittleEndian.Uint32(raw[16:20])    // native x86_64/arm64 byte order, never crosses the network
	ev.dport = binary.BigEndian.Uint16(raw[20:22])     // raw sin_port/sin6_port bytes: always network (big-endian) order
	ev.family = raw[22]                                // 4 or 6, written by connect.c; raw[23] is declared padding
	copy(ev.daddr[:], raw[24:40])                      // raw address bytes, read octet-by-octet, no numeric byte-order question at all
	copy(ev.comm[:], raw[40:56])
	return ev, true
}

// isLocalModelPort reports whether a loopback connection on this port is worth
// keeping: Ollama's own, and the two vLLM defaults. Everything else on loopback
// is local chatter (a database, an editor's language server, a package manager)
// and would drown the real finding.
//
// One list, so that the filter and anything classifying a destination cannot
// disagree. tokenfuse's radar had two and they differed on 8001: its classifier
// called that port vLLM while its filter dropped the packet first, so the
// branch naming it could never run.
func isLocalModelPort(port uint16) bool {
	return port == 11434 || port == 8000 || port == 8001
}

// destination renders one captured connection's destination, resolving the
// address back to a known LLM hostname when it matches one.
//
// net.JoinHostPort, not fmt.Sprintf("%s:%d"), and that is the whole reason this
// is a function rather than two lines at the call site: an IPv6 address
// contains colons, so "2001:db8::1" and port 443 concatenate into a string
// nothing can parse back, and every consumer downstream (the egress connector,
// matchLLM's normalizeHost, an operator reading the report) splits on the last
// colon. JoinHostPort brackets it.
func destination(ip net.IP, port uint16, llmIPs map[string]string) string {
	host := ip.String()
	if resolved, ok := llmIPs[host]; ok {
		host = resolved
	}
	return net.JoinHostPort(host, itoa(port))
}

// itoa avoids pulling strconv in for one call in a file that otherwise needs
// nothing but encoding/binary and net.
func itoa(port uint16) string {
	if port == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for port > 0 {
		i--
		b[i] = byte('0' + port%10)
		port /= 10
	}
	return string(b[i:])
}

// SkippedCounts is what the sensor saw and deliberately did not report, per
// reason, read out of the BPF map at the end of a capture. It mirrors struct
// skipped_counts in connect.c field for field.
//
// It exists because "zero flows captured" had three indistinguishable meanings
// until it did: nothing connected, everything connected over a family this
// sensor ignores, or the ring buffer filled and real evidence was dropped.
// AGENTS.md invariant 4 requires idryx to say what it could not observe rather
// than present a partial graph as a complete one, and a silent zero is exactly
// the shape that invariant forbids.
type SkippedCounts struct {
	// OtherFamily is connect() calls over neither AF_INET nor AF_INET6:
	// AF_UNIX, netlink and friends. Out of scope by design, counted so that a
	// quiet capture on a busy host is explainable rather than mysterious.
	OtherFamily uint64
	// Unreadable is a sockaddr the kernel would not let the program read.
	Unreadable uint64
	// RingbufFull is the one that matters: a connection this sensor wanted to
	// report and could not, so the capture is incomplete in a way no other
	// number would show.
	RingbufFull uint64
}

// Any reports whether anything at all went uncounted, so a caller can decide
// between staying quiet and telling an operator what the capture missed.
func (s SkippedCounts) Any() bool {
	return s.OtherFamily > 0 || s.Unreadable > 0 || s.RingbufFull > 0
}

// Lost reports whether evidence in scope was dropped, as opposed to traffic
// this sensor never wanted. The distinction is the whole point of counting per
// reason: a million AF_UNIX connects say nothing is wrong, and one full ring
// buffer says the capture cannot be trusted to be complete.
func (s SkippedCounts) Lost() bool {
	return s.RingbufFull > 0
}
