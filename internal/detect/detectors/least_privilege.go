package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// LeastPrivilege compares granted permissions against observed usage and flags
// the grants that are never exercised — the right-sizing recommendation at the
// heart of least-privilege. It only fires for identities that have usage data
// (at least one permission marked Used); without usage data it stays silent to
// avoid recommending removal of permissions that may simply be unobserved.
type LeastPrivilege struct{}

func NewLeastPrivilege() *LeastPrivilege { return &LeastPrivilege{} }

func (d *LeastPrivilege) Name() string { return "least_privilege" }

func (d *LeastPrivilege) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if len(id.Permissions) == 0 {
			continue
		}
		hasUsage := false
		var unused []string
		unusedAdmin := false
		for _, p := range id.Permissions {
			if p.Used {
				hasUsage = true
				continue
			}
			unused = append(unused, p.Name)
			if p.Admin {
				unusedAdmin = true
			}
		}
		// No usage signal for this identity, or everything is used — nothing to
		// recommend.
		if !hasUsage || len(unused) == 0 {
			continue
		}
		sev := model.SeverityMedium
		if unusedAdmin {
			// An unused admin grant is the highest-value reduction.
			sev = model.SeverityHigh
		}
		sort.Strings(unused)
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf("%d/%d granted permissions unused, recommend revoking: %s",
				len(unused), len(id.Permissions), strings.Join(unused, ", ")),
		})
	}
	return alerts
}
