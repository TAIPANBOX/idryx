package detectors

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// mcpDriftWindow bounds how far back an mcp_drift event still counts toward
// an mcp_drift finding, the same 30-day "recent behavior" horizon as
// tainted_agent and runaway_agent's spendWindow.
const mcpDriftWindow = 30 * 24 * time.Hour

// mcpDriftRepeatThreshold is the count at which repeat mcp_drift events
// escalate a finding to critical (see the severity comment in Detect below).
const mcpDriftRepeatThreshold = 2

// MCPDrift flags AI agents with at least one mcp_drift event: an MCP server
// the agent talks to changed its config or exposed tooling out from under it
// (agent-passport SPEC §6.2 mcp_drift, source "tokenfuse"). This is a
// supply-chain/config-integrity signal distinct from the other two MCP
// detectors: shadow_mcp flags a server that was never sanctioned, and
// agent_shadow_tool flags a tool reachable through one; mcp_drift instead
// flags a previously-known, presumably sanctioned server changing without a
// corresponding change on idryx's side: exactly the kind of drift that
// precedes a tool-poisoning or config-tampering incident. Like tainted_agent,
// a single occurrence already fires: the change itself is the anomaly, not
// its frequency. Severity escalates on repeat drift within the window (an
// unstable or actively-tampered server) and on standing privilege.
type MCPDrift struct{}

func NewMCPDrift() *MCPDrift { return &MCPDrift{} }

func (d *MCPDrift) Name() string { return "mcp_drift" }

func (d *MCPDrift) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		count := 0
		for _, e := range id.Events {
			if e.Type != model.EventMCPDrift {
				continue
			}
			if now().Sub(e.Time) > mcpDriftWindow {
				continue
			}
			count++
		}
		if count == 0 {
			continue
		}

		// One drift event already fires at high; a repeat within the
		// window, or standing privilege/admin access on the agent, raises
		// it to critical.
		sev := model.SeverityHigh
		if count >= mcpDriftRepeatThreshold || id.Privileged || id.HasAdmin() {
			sev = model.SeverityCritical
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf(
				"%d MCP config/tooling drift event(s) within %s (supply-chain integrity signal)",
				count, mcpDriftWindow),
		})
	}
	return alerts
}
