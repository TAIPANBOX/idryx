package ebpfcapture

import "encoding/binary"

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
// file imports encoding/binary and nothing else, so a darwin or windows build
// still pulls in zero cilium/ebpf packages.

// connEventSize is sizeof(struct conn_event) in connect.c: 4 (pid) + 2
// (dport) + 4 (daddr) + 16 (comm) + 2 (explicit trailing pad) = 28 bytes.
// decodeConnEvent refuses anything shorter, so a future connect.c change
// that isn't mirrored here fails loudly (a skipped record, logged by the
// caller) rather than silently misreading a shifted layout.
const connEventSize = 28

// decodedConnEvent is conn_event's already-byte-order-resolved form: dport
// and daddr converted out of connect.c's deliberately-raw wire bytes (see
// connect.c's own doc comment for why that conversion happens here, not in
// the eBPF program).
type decodedConnEvent struct {
	pid   uint32
	dport uint16
	daddr [4]byte
	comm  [16]byte
}

// decodeConnEvent parses one ring buffer record against connect.c's struct
// conn_event layout exactly (see connEventSize). false means the record is
// the wrong size -- a mismatched connect.c/decode.go pair, or ring buffer
// corruption -- and is skipped rather than panicking a live capture over one
// bad record.
func decodeConnEvent(raw []byte) (decodedConnEvent, bool) {
	if len(raw) < connEventSize {
		return decodedConnEvent{}, false
	}
	var ev decodedConnEvent
	ev.pid = binary.LittleEndian.Uint32(raw[0:4]) // native x86_64/arm64 byte order, never crosses the network
	ev.dport = binary.BigEndian.Uint16(raw[4:6])  // raw sockaddr_in.sin_port bytes: always network (big-endian) order
	copy(ev.daddr[:], raw[6:10])                  // raw sockaddr_in.sin_addr bytes, read octet-by-octet, no numeric byte-order question at all
	copy(ev.comm[:], raw[10:26])
	return ev, true
}
