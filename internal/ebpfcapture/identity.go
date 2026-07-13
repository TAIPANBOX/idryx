// Package ebpfcapture is idryx's eBPF network-behavior sensor: a Go-native
// (cilium/ebpf) port of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar), scoped to what that sensor actually ships
// today, not idryx-plan.md's original, larger Phase 4 spec. Beaconing/
// periodogram detection, JA3/JA4 TLS fingerprinting, DNS-tunnel detection,
// and full identity correlation (resolving a captured process to a real
// governed agent/service identity, not just its process name) are all
// explicitly deferred -- see SECURITY.md's "eBPF network sensor" section
// and idryx-plan.md's own Phase 4 note.
//
// This file has no build tag: it defines the identity-naming convention
// capture_linux.go's Linux-only capture loop uses to label a flow, kept
// separate so internal/detect/detectors' unmanaged_egress detector (which
// must build on every platform idryx supports, unlike the capture code
// itself) can recognize these identities without importing anything
// platform-specific.
package ebpfcapture

// IdentityPrefix marks a graph identity ID as sourced from raw eBPF
// capture: a process observed making a real network connection, with no
// attribution to any governed agent or service identity. See Identity.
const IdentityPrefix = "proc:"

// Identity returns the graph identity ID a captured connection is recorded
// under, from the connecting process's comm (its short name, e.g. "curl",
// "python3", as bpf_get_current_comm reports it -- see connect.c).
//
// Every process sharing a comm is grouped into one identity. This is
// deliberately coarse, not a bug to fix later without notice: eBPF alone
// observes a raw connect() syscall, nothing more, so it cannot tell two
// concurrent instances of the same binary apart, and it cannot resolve a
// process to a specific agent:// identity the way a Passport or an
// agent-event envelope can (the identity a *governed* connector would
// report). A "proc:"-prefixed identity is idryx's honest way of saying
// "real network activity was observed here, attributable only to a
// process name" -- see the unmanaged_egress detector, which exists
// specifically to surface that this is the only evidence idryx has for
// these identities.
func Identity(comm string) string {
	return IdentityPrefix + comm
}
