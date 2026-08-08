package ebpfcapture

import "bytes"

// This file has no build tag: the /proc/<pid>/environ FORMAT is a fact about
// Linux, but parsing a NUL-separated block is not, and a parser that can only
// be tested where the kernel provides its input is tested only there. The read
// itself stays in environ_linux.go.

// envVar is the environment variable agent-passport SPEC 3.3 reserves for a
// process to carry its own agent:// identity. The name is the spec's, not
// ours, and must not be aliased or extended locally: 3.3 reserves it precisely
// so two products cannot disagree about the same string.
const envVar = "AGENT_PASSPORT_ID"

// findEnv extracts one variable from the NUL-separated block /proc/<pid>/environ
// returns. Split on its own file rather than inline so it can be tested on any
// platform: the format is a fact about Linux, but parsing it is not.
//
// The match is exact on `NAME=`, not a prefix or a contains: `MY_AGENT_PASSPORT_ID`
// and `AGENT_PASSPORT_IDX` are different variables and neither is this one. A
// loose match here would let an unrelated variable name an agent, which is the
// same class of mistake as repairing a malformed URI.
func findEnv(environ []byte, name string) string {
	prefix := append([]byte(name), '=')
	for _, entry := range bytes.Split(environ, []byte{0}) {
		if bytes.HasPrefix(entry, prefix) {
			return string(entry[len(prefix):])
		}
	}
	return ""
}
