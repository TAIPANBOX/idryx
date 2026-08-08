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

import "strconv"

// IdentityPrefix marks a graph identity ID as sourced from raw eBPF
// capture: a process observed making a real network connection, with no
// attribution to any governed agent or service identity. See Identity.
const IdentityPrefix = "proc:"

// Identity returns the graph identity ID a captured connection is recorded
// under: the connecting process's comm (its short name, e.g. "curl",
// "python3", as bpf_get_current_comm reports it -- see connect.c), qualified
// by its cgroup when the kernel gave one.
//
//	Identity("curl", 0)      == "proc:curl"
//	Identity("curl", 8471)   == "proc:curl@cg8471"
//
// **Why the cgroup is in the identity rather than beside it.** The egress wire
// shape this feeds is exactly {time, identity, destination, bytes} (see
// flow.go), and it is shared with a connector that parses logs idryx did not
// produce. The identity string is the only field that can carry more without
// changing a format somebody else writes.
//
// **Why the prefix does not change.** unmanaged_egress selects on "proc:" and
// nothing else. A new prefix would make it stop seeing these identities, and
// it would stop silently: no error, no finding, just a detector that reports
// nothing for the exact case it exists for. A suffix is additive, so a
// qualified identity is still matched by every selector that matched the
// unqualified one.
//
// **What a cgroup id is and is not.** It is the cgroup's inode: kernel-assigned,
// unique while that cgroup lives, and reused afterwards. Two processes in one
// container share it, which is exactly the grouping wanted here. It is NOT a
// container id, it does not survive a restart, and a process outside any
// container carries the root cgroup's, shared with everything else on the host.
// So it sharpens attribution without ever asserting identity: two connections
// with the same suffix came from the same cgroup, and that is the whole claim.
//
// **What it fixes.** comm alone is a string the process chose, changeable with
// prctl, and shared by every instance of a binary: fifty containers each
// running python3 collapsed into one identity called "proc:python3", and an
// evasive process could join or leave that group at will. The cgroup id cannot
// be rewritten by the process it describes.
//
// Still absent, and named so nobody reads this as more than it is: resolving
// either of these to a governed agent:// identity. Nothing in the stack records
// that a process IS an agent, so this remains "real network activity was
// observed here, attributable to a process name and a cgroup" -- which is what
// unmanaged_egress exists to surface.
func Identity(comm string, cgroupID uint64) string {
	if cgroupID == 0 {
		return IdentityPrefix + comm
	}
	return IdentityPrefix + comm + "@cg" + strconv.FormatUint(cgroupID, 10)
}
