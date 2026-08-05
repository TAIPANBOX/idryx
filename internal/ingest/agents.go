package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// agentInventory is the input idryx reads for the agents source: AI agents and
// the tools/scopes they can invoke, plus the identity each acts on behalf of.
// This is intentionally registry-agnostic — MCP registries, agent frameworks,
// and gateways all reduce to "agent X, running on R, acting as P, with tools T".
type agentInventory struct {
	Agents []agentRecord `json:"agents"`
}

type agentRecord struct {
	ID         string   `json:"id"`
	Runtime    string   `json:"runtime"`
	OnBehalfOf string   `json:"onBehalfOf"` // identity ID the agent delegates from (one hop; see model.Identity.OnBehalfOf)
	Owner      string   `json:"owner"`
	Created    string   `json:"created"`   // when the agent's credential was issued (RFC3339, optional)
	Tools      []string `json:"tools"`     // tool/scope names the agent may call
	UsedTools  []string `json:"usedTools"` // tools actually observed in use (optional)
}

// Agents parses the agent inventory into agent identities. Each tool becomes a
// permission; a tool whose name implies broad action (admin/delete/write-all)
// is flagged admin-equivalent so the over-privileged detector catches it too.
//
// The returned Report counts how many agent records were read and how many
// carried a non-empty "created" that failed to parse as RFC3339. That field
// is optional, so a missing "created" is not malformed -- but a present,
// unparseable one used to be silently absorbed into a zero Created (same
// outcome as never having supplied it), which makes GenerateRotation treat
// the agent as nothing-to-rotate and stale_nhi skip it: a typo silently
// removing an agent from two checks. Unlike the four event connectors, a
// malformed "created" does not drop the agent record itself, only leaves
// Created zero as before; see reportIngest in cmd/idryx/main.go, which
// surfaces a nonzero Malformed count on stderr.
func Agents(data []byte) ([]model.Identity, Report, error) {
	var in agentInventory
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, Report{}, err
	}

	var rep Report
	out := make([]model.Identity, 0, len(in.Agents))
	for _, a := range in.Agents {
		rep.Records++
		id := model.Identity{
			ID:      a.ID,
			Type:    model.IdentityAgent,
			Source:  "agents",
			Owner:   a.Owner,
			Runtime: a.Runtime,
		}
		if a.OnBehalfOf != "" {
			id.OnBehalfOf = []string{a.OnBehalfOf}
		}
		if a.Created != "" {
			if t, err := time.Parse(time.RFC3339, a.Created); err == nil {
				id.Created = t
			} else {
				rep.Malformed++
			}
		}
		used := make(map[string]bool, len(a.UsedTools))
		for _, t := range a.UsedTools {
			used[t] = true
		}
		for _, tool := range a.Tools {
			id.Permissions = append(id.Permissions, model.Permission{
				Name:  tool,
				Admin: isHighRiskTool(tool),
				Used:  used[tool],
			})
		}
		id.Privileged = id.HasAdmin()
		out = append(out, id)
	}
	return out, rep, nil
}

// isHighRiskTool flags tool/scope names that grant broad or destructive action.
func isHighRiskTool(tool string) bool {
	t := strings.ToLower(tool)
	for _, k := range []string{"admin", "delete", "write_all", "exec", "shell", "*"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}
