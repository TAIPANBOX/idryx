package detectors

import (
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// NewDevice flags a privileged identity logging in from a device it has not used
// before. The first-ever device is treated as the baseline, not an alert.
type NewDevice struct{}

func NewNewDevice() *NewDevice { return &NewDevice{} }

func (d *NewDevice) Name() string { return "new_device" }

func (d *NewDevice) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.Privileged {
			continue
		}
		seen := make(map[string]bool)
		for _, e := range id.Events {
			if e.Type != model.EventLogin || e.Outcome != "SUCCESS" || e.Device == "" {
				continue
			}
			if !seen[e.Device] && len(seen) > 0 {
				alerts = append(alerts, model.Alert{
					Detector:   d.Name(),
					IdentityID: id.ID,
					Severity:   model.SeverityHigh,
					Time:       e.Time,
					Summary:    fmt.Sprintf("privileged login from new device %q", e.Device),
				})
			}
			seen[e.Device] = true
		}
	}
	return alerts
}
