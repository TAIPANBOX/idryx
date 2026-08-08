package ebpfcapture

import "time"

// This file has no build tag: Flow and its conversion to the egress wire
// shape are plain data, needed by cmd/idryx's ebpf-capture command on every
// platform (that command must compile everywhere, even though Run itself
// -- capture_linux.go -- only exists on Linux).

// Flow is one captured connection, already filtered and (when it matches a
// known LLM provider) resolved to a hostname -- the shape EgressFlow exists
// to consume, one field at a time: Time -> time, Identity -> identity,
// Destination -> destination. Bytes is always 0: sys_enter_connect fires
// before any data transfer, so there is nothing to report yet, the same
// honest limitation tokenfuse's own sensor has (see crates/radar's README).
type Flow struct {
	Time        time.Time
	Identity    string
	Destination string
	PID         uint32
	// CgroupID is the kernel-assigned cgroup the connecting process was in,
	// zero when the kernel did not provide one. It is already folded into
	// Identity (see identity.go); it is kept separately here because a caller
	// streaming flows live may want to group by it without parsing the
	// identity string back apart, and because a string that has been parsed
	// out of another string is the kind of thing that quietly stops matching.
	CgroupID uint64
	// Observed is what the sensor saw with its own eyes: always the
	// `proc:<comm>[@cg<id>]` form, whatever Identity ended up being.
	//
	// The two differ exactly when the process named itself through
	// AGENT_PASSPORT_ID (agent-passport SPEC 3.3) and Identity became the
	// claimed agent:// URI. Keeping the observation is not redundancy: a claim
	// is a statement by the subject, and the moment a consumer decides not to
	// believe one, the only thing left is what was actually seen. Dropping it
	// would mean a process could erase the sensor's own observation by writing
	// a variable, which is a strange power to hand the thing being observed.
	Observed string
}

// EgressLog and EgressFlow are Flow's wire shape: exactly
// internal/ingest/egress.go's own {flows:[{time,identity,destination,bytes}]}
// envelope, deliberately duplicated here rather than imported (that
// package's egressLog/egressFlow are unexported -- this is the one place
// outside internal/ingest that needs to construct, not just consume, that
// exact shape). Keep field names and JSON tags in lockstep with egress.go's
// own if either ever changes.
type EgressLog struct {
	Flows []EgressFlow `json:"flows"`
}

type EgressFlow struct {
	Time        string `json:"time"`
	Identity    string `json:"identity"`
	Destination string `json:"destination"`
	Bytes       int64  `json:"bytes"`
}

// ToEgressLog converts captured flows into the wire shape
// internal/ingest/egress.go's Egress parses, e.g. for
// `idryx ebpf-capture -out captured.json` followed by
// `idryx detect --load egress:captured.json`.
func ToEgressLog(flows []Flow) EgressLog {
	out := EgressLog{Flows: make([]EgressFlow, 0, len(flows))}
	for _, f := range flows {
		out.Flows = append(out.Flows, EgressFlow{
			// RFC3339Nano, not RFC3339, and the difference is the whole point
			// of taking the timestamp from the kernel at all: RFC3339 has no
			// fractional part, so it rounds every flow to the second on the way
			// out. Two connections 200ms apart become simultaneous, and a
			// beacon's jitter becomes an artefact of this line rather than a
			// property of the traffic.
			//
			// The reader is unaffected: internal/ingest/egress.go parses with
			// time.Parse(time.RFC3339, ...), and Go accepts a fractional second
			// against that layout whether or not the layout mentions one. An
			// older log without the fraction still reads identically.
			Time:        f.Time.UTC().Format(time.RFC3339Nano),
			Identity:    f.Identity,
			Destination: f.Destination,
			Bytes:       0,
		})
	}
	return out
}
