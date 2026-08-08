//go:build linux

package ebpfcapture

import (
	"os"
	"strconv"
)

// claimedAgentURI reads AGENT_PASSPORT_ID out of a live process's environment
// and returns its value, or "" when there is nothing usable there.
//
// **Every failure is "not declared", and that is required rather than lenient.**
// SPEC 3.3: a consumer "MUST treat a failed read as 'not declared'". The
// process may have exited between the connect() this sensor observed and this
// read, which is the normal case for a short-lived agent and therefore for
// exactly the agent worth attributing. It may belong to another user, in
// another namespace, or the kernel may simply refuse. None of those is an
// error worth failing a capture over, and none of them is evidence of
// anything: an absent claim and an unreadable one look identical from here,
// deliberately, because treating unreadable as suspicious would make every
// short-lived process a finding.
//
// **One read, of one process, that this sensor already saw.** 3.3 also says a
// consumer "MUST NOT retry in a way that turns an observation into a scan of
// processes it has no other reason to touch". So there is no retry, no walk of
// /proc, and no lookup of a pid this sensor has not just observed connecting.
// The read is a side effect of an observation, never a search.
func claimedAgentURI(pid uint32) string {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/environ")
	if err != nil {
		return "" // exited, permission, namespace: all "not declared"
	}
	return findEnv(data, envVar)
}
