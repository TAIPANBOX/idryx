package detectors

import (
	"fmt"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// BOMIncomplete flags AI agents missing the governance-critical fields an
// Agent-BOM (internal/bom) needs to prove what the agent is made of: Owner
// (who is accountable for it), Runtime (where it executes), and Attestation
// (how its identity is bound to a workload; agent-passport SPEC Sec 4.3
// "none" counts as missing here too, the same treatment attestation_missing
// gives it). Unlike attestation_missing, this fires regardless of standing
// privilege: an inventory gap is worth surfacing on every agent, not only
// privileged ones, because you cannot tell which agents are safe to ignore
// until the BOM itself is complete enough to trust.
type BOMIncomplete struct{}

func NewBOMIncomplete() *BOMIncomplete { return &BOMIncomplete{} }

func (d *BOMIncomplete) Name() string { return "bom_incomplete" }

func (d *BOMIncomplete) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		var missing []string
		if id.Owner == "" {
			missing = append(missing, "owner")
		}
		if id.Runtime == "" {
			missing = append(missing, "runtime")
		}
		if id.Attestation == "" || id.Attestation == "none" {
			missing = append(missing, "attestation")
		}
		if len(missing) == 0 {
			continue
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   model.SeverityMedium,
			Time:       now(),
			Summary:    fmt.Sprintf("agent-bom incomplete: missing %s", strings.Join(missing, ", ")),
		})
	}
	return alerts
}
