package detectors

import (
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// ShadowMCP flags MCP servers that are in use but absent from the sanctioned
// registry (OWASP MCP Top 10: Shadow MCP Servers). An unsanctioned server is an
// unreviewed perimeter; one that also exposes high-risk tools (shell/exec/admin)
// compounds shadow MCP with tool-poisoning exposure and is treated as critical.
type ShadowMCP struct{}

func NewShadowMCP() *ShadowMCP { return &ShadowMCP{} }

func (d *ShadowMCP) Name() string { return "shadow_mcp" }

func (d *ShadowMCP) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if id.Type != model.IdentityMCPServer || !id.Shadow {
			continue
		}
		sev := model.SeverityHigh
		summary := "unsanctioned MCP server in use (shadow MCP)"
		if id.HasAdmin() {
			sev = model.SeverityCritical
			summary = "unsanctioned MCP server exposes high-risk tools (shadow MCP + tool poisoning)"
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    summary,
		})
	}
	return alerts
}
