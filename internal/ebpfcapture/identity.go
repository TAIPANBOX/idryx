// Package ebpfcapture is idryx's eBPF network-behavior sensor: a Go-native
// (cilium/ebpf) port of tokenfuse's own eBPF sensor
// (tokenfuse/crates/radar), and since grown past it: the sensor observes both
// address families, counts what it did not report, carries the cgroup and the
// kernel's own timestamp, and reads a process's self-declared agent identity
// (agent-passport SPEC 3.3).
//
// Of idryx-plan.md's original Phase 4 spec, JA3/JA4 TLS fingerprinting is
// **decided against** rather than deferred: it needs the ClientHello, and
// SECURITY.md promises this sensor never reads payloads or inspects TLS.
// Beaconing and DNS-tunnel detection are still deferred, and neither needs a
// payload; beaconing works from the connection timing this sensor now takes
// from the kernel clock. See SECURITY.md's "eBPF network sensor" section.
//
// This file has no build tag: it defines the identity-naming convention
// capture_linux.go's Linux-only capture loop uses to label a flow, kept
// separate so internal/detect/detectors' unmanaged_egress detector (which
// must build on every platform idryx supports, unlike the capture code
// itself) can recognize these identities without importing anything
// platform-specific.
package ebpfcapture

import (
	"strconv"
	"strings"

	"github.com/TAIPANBOX/agent-stack-go/passport"
)

// IdentityPrefix marks a graph identity ID as sourced from raw eBPF
// capture: a process observed making a real network connection, with no
// attribution to any governed agent or service identity. See Identity.
const IdentityPrefix = "proc:"

// ClaimedPrefix marks a graph identity ID the connecting process named
// ITSELF, by carrying an agent:// URI in AGENT_PASSPORT_ID (agent-passport
// SPEC 3.3).
//
// The prefix exists because 3.3 requires it in substance: "a consumer MUST
// record an identity learned this way as claimed", and "an observer that
// reports it SHOULD make the distinction visible in what it reports". A bare
// agent:// URI in the identity field would be indistinguishable from one a
// Passport or an IAM connector established, and the difference is the whole
// point: a process writes its own environment, so it can name another agent
// or one that was never issued.
//
// So the two prefixes say different things and neither is stronger than it
// sounds. `proc:` is "something ran here and I can only describe it".
// `claimed:` is "something ran here and told me who it is". Only a governed
// connector produces an identity with no prefix at all.
const ClaimedPrefix = "claimed:"

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

// ClaimedIdentity returns the graph identity ID for a process that named
// itself through AGENT_PASSPORT_ID (agent-passport SPEC 3.3), or "" when the
// claim is unusable and the caller should fall back to Identity.
//
//	ClaimedIdentity("agent://acme.example/support/bot")  == "claimed:agent://acme.example/support/bot"
//	ClaimedIdentity("not-a-uri")                          == ""
//	ClaimedIdentity("")                                   == ""
//
// Validation comes from agent-stack-go, never from a pattern written here.
// AGENTS.md invariant 3 says the shared module is the only source of the wire
// types, and an agent:// URI is one: a second regular expression in this
// package would be the drift that invariant exists to prevent, and it would
// drift in the direction of accepting more, because a local check is written
// against the examples somebody had in front of them.
//
// An unusable claim is dropped rather than repaired, which SPEC 3.3 requires
// in those words: "a value that does not parse MUST be treated as absent
// rather than repaired or truncated". Repairing it would invent an identity,
// and this is the one place in the sensor where inventing one is easy.
func ClaimedIdentity(agentURI string) string {
	if agentURI == "" {
		return ""
	}
	if err := passport.ValidateAgentURI(agentURI); err != nil {
		return ""
	}
	return ClaimedPrefix + agentURI
}

// IsClaimed reports whether a graph identity ID is one a process asserted
// about itself. Consumers use it to keep a claimed identity out of any
// control that requires an attested one, which SPEC 3.3 makes a MUST NOT.
func IsClaimed(identityID string) bool {
	return strings.HasPrefix(identityID, ClaimedPrefix)
}
