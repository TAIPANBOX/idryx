package ingest

import (
	"encoding/json"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// egressLog is a generic network-egress export: which identity connected to
// which destination host, and when. It is intentionally connector-agnostic —
// VPC flow logs, proxy logs, and CASB exports all reduce to this shape.
type egressLog struct {
	Flows []egressFlow `json:"flows"`
}

type egressFlow struct {
	Time        string `json:"time"`
	Identity    string `json:"identity"`
	Destination string `json:"destination"` // host or host:port
	Bytes       int64  `json:"bytes"`
}

// Egress parses a network-egress log into egress events. These carry the
// destination host in Resource; the shadow_ai detector reasons over them.
func Egress(data []byte) ([]model.Event, error) {
	var l egressLog
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(l.Flows))
	for _, f := range l.Flows {
		t, err := time.Parse(time.RFC3339, f.Time)
		if err != nil {
			continue
		}
		out = append(out, model.Event{
			Time:       t,
			IdentityID: f.Identity,
			Type:       model.EventEgress,
			Outcome:    "SUCCESS",
			Resource:   f.Destination,
		})
	}
	return out, nil
}
