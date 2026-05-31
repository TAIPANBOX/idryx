package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// AgentShadowTool links the agent and MCP layers: it flags an AI agent whose
// declared tools are exposed by an unsanctioned (shadow) MCP server. shadow_mcp
// flags the rogue server; this flags the agents actually wired to it — the path
// by which a poisoned tool reaches a model (OWASP MCP Top 10 + LLM06). A match
// on a high-risk tool (shell/exec/admin) is treated as critical.
type AgentShadowTool struct{}

func NewAgentShadowTool() *AgentShadowTool { return &AgentShadowTool{} }

func (d *AgentShadowTool) Name() string { return "agent_shadow_tool" }

func (d *AgentShadowTool) Detect(g graph.Reader) []model.Alert {
	// Tools exposed by shadow MCP servers, mapped to whether the tool is high-risk.
	shadowTools := map[string]bool{}
	for _, id := range g.Identities() {
		if id.Type != model.IdentityMCPServer || !id.Shadow {
			continue
		}
		for _, p := range id.Permissions {
			shadowTools[p.Name] = shadowTools[p.Name] || p.Admin
		}
	}
	if len(shadowTools) == 0 {
		return nil
	}

	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		var matched []string
		risky := false
		for _, p := range id.Permissions {
			hr, ok := shadowTools[p.Name]
			if !ok {
				continue
			}
			matched = append(matched, p.Name)
			if hr || p.Admin {
				risky = true
			}
		}
		if len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		sev := model.SeverityHigh
		if risky {
			sev = model.SeverityCritical
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf("agent uses tool(s) from an unsanctioned MCP server: %s",
				strings.Join(matched, ", ")),
		})
	}
	return alerts
}
