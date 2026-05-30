package detectors

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// staleAfter is how long an NHI may go unused before it is flagged. 90 days is a
// common rotation/cleanup window.
const staleAfter = 90 * 24 * time.Hour

// now is overridable in tests for deterministic age math.
var now = time.Now

// StaleNHI flags non-human identities that have not been used within staleAfter,
// or were never used since creation. These are prime cleanup/rotation targets.
type StaleNHI struct{}

func NewStaleNHI() *StaleNHI { return &StaleNHI{} }

func (d *StaleNHI) Name() string { return "stale_nhi" }

func (d *StaleNHI) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() {
			continue
		}
		last := id.LastUsed
		ref := "last used"
		if last.IsZero() {
			last = id.Created
			ref = "created"
		}
		if last.IsZero() {
			continue // no timeline to judge
		}
		age := now().Sub(last)
		if age < staleAfter {
			continue
		}
		sev := model.SeverityMedium
		if id.HasAdmin() {
			sev = model.SeverityHigh
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    fmt.Sprintf("NHI stale: %s %dd ago", ref, int(age.Hours()/24)),
		})
	}
	return alerts
}

// OverPrivilegedNHI flags non-human identities holding admin-equivalent
// permissions. Excessive standing privilege on an NHI is the highest-value
// target for an attacker.
type OverPrivilegedNHI struct{}

func NewOverPrivilegedNHI() *OverPrivilegedNHI { return &OverPrivilegedNHI{} }

func (d *OverPrivilegedNHI) Name() string { return "over_privileged_nhi" }

func (d *OverPrivilegedNHI) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() || !id.HasAdmin() {
			continue
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   model.SeverityHigh,
			Time:       now(),
			Summary:    "NHI holds admin-equivalent permissions",
		})
	}
	return alerts
}

// OrphanedNHI flags non-human identities with no known owner. An unowned NHI is
// one nobody will rotate, revoke, or notice when compromised.
type OrphanedNHI struct{}

func NewOrphanedNHI() *OrphanedNHI { return &OrphanedNHI{} }

func (d *OrphanedNHI) Name() string { return "orphaned_nhi" }

func (d *OrphanedNHI) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() || id.Owner != "" {
			continue
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   model.SeverityLow,
			Time:       now(),
			Summary:    "NHI has no mapped owner",
		})
	}
	return alerts
}
