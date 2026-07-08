package detectors

import (
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// ExcessiveAgency measures an agent's blast radius: the permissions it reaches
// through its delegation chain (OnBehalfOf, root-first, up to the ultimate
// principal — agent-passport SPEC §5). An agent that can act, transitively, as
// an admin identity, or as any admin principal named anywhere in its chain, is
// the highest-value target when compromised by prompt injection (OWASP LLM06
// Excessive Agency).
//
// It is backend-agnostic: it indexes the identities returned by graph.Reader and
// walks OnBehalfOf itself, so it works over the in-memory or Postgres graph.
type ExcessiveAgency struct{}

func NewExcessiveAgency() *ExcessiveAgency { return &ExcessiveAgency{} }

func (d *ExcessiveAgency) Name() string { return "excessive_agency" }

func (d *ExcessiveAgency) Detect(g graph.Reader) []model.Alert {
	index := map[string]*model.Identity{}
	for _, id := range g.Identities() {
		index[id.ID] = id
	}

	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		chain := graph.WalkDelegationChain(index, id.ID)
		adminVia, ok := adminInChain(index, chain)
		if !ok {
			continue
		}
		// An agent that directly holds admin is over_privileged_nhi's concern;
		// excessive_agency is specifically about reaching admin via delegation.
		if adminVia == id.ID {
			continue
		}
		sev := model.SeverityHigh
		if len(chain) > 2 {
			// Privilege reached through multiple hops is easy to miss and harder
			// to reason about — treat deep chains as more severe.
			sev = model.SeverityCritical
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf("agent reaches admin via %s (delegation depth %d)",
				adminVia, len(chain)-1),
		})
	}
	return alerts
}

// adminInChain reports the first identity in the chain holding admin-equivalent
// permissions, if any.
func adminInChain(index map[string]*model.Identity, chain []string) (string, bool) {
	for _, link := range chain {
		if node, ok := index[link]; ok && node.HasAdmin() {
			return link, true
		}
	}
	return "", false
}
