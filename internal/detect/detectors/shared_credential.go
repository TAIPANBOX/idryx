package detectors

import (
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// SharedCredential flags non-human identities (like AWS Access Keys or GCP SAs)
// whose credentials are used across multiple distinct network environments (IPs),
// countries, or client devices within the active log window. NHIs are intended
// to run in fixed automated environments; multi-origin usage indicates credential
// sharing or key leakage.
type SharedCredential struct{}

func NewSharedCredential() *SharedCredential { return &SharedCredential{} }

func (d *SharedCredential) Name() string { return "shared_credential" }

func (d *SharedCredential) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() {
			continue
		}

		ips := make(map[string]bool)
		countries := make(map[string]bool)
		devices := make(map[string]bool)

		for _, e := range id.Events {
			if e.Outcome != "SUCCESS" && e.Outcome != "" {
				continue
			}
			if e.IP != "" {
				ips[e.IP] = true
			}
			if e.Country != "" {
				countries[e.Country] = true
			}
			if e.Device != "" {
				devices[e.Device] = true
			}
		}

		// Flag if used across multiple origins (threshold > 2 distinct values)
		if len(ips) > 2 || len(countries) > 2 || len(devices) > 2 {
			summary := fmt.Sprintf("NHI credential sharing/leakage: used across %d IPs, %d countries, %d devices",
				len(ips), len(countries), len(devices))
			alerts = append(alerts, model.Alert{
				Detector:   d.Name(),
				IdentityID: id.ID,
				Severity:   model.SeverityHigh,
				Time:       now(),
				Summary:    summary,
			})
		}
	}
	return alerts
}
