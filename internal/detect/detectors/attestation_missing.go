package detectors

import (
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// AttestationMissing flags AI agents that already hold privileged/admin
// access but have no attestation on record for their identity binding
// (agent-passport SPEC §4.3: attestation.method "none", or absent entirely
// from a source — e.g. one that has never ingested a Passport document —
// that doesn't set it at all). This is the SPEC's own worked example of
// what idryx SHOULD surface (§4.3): "none" is a legal and honest posture,
// but it must be *visible*, especially on an identity that can already do
// damage. Unlike runaway_agent, this fires on standing privilege alone —
// no spend incident required.
type AttestationMissing struct{}

func NewAttestationMissing() *AttestationMissing { return &AttestationMissing{} }

func (d *AttestationMissing) Name() string { return "attestation_missing" }

func (d *AttestationMissing) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		if !(id.Privileged || id.HasAdmin()) {
			continue
		}
		if id.Attestation != "" && id.Attestation != "none" {
			continue
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   model.SeverityHigh,
			Time:       now(),
			Summary:    fmt.Sprintf("privileged agent has no attestation on record (attestation=%s)", attestationLabel(id.Attestation)),
		})
	}
	return alerts
}
