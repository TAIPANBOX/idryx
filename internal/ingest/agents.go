package ingest

import (
	"encoding/json"
	"strings"

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
	OnBehalfOf string   `json:"onBehalfOf"` // identity ID the agent delegates from
	Owner      string   `json:"owner"`
	Tools      []string `json:"tools"`     // tool/scope names the agent may call
	UsedTools  []string `json:"usedTools"` // tools actually observed in use (optional)
}

// Agents parses the agent inventory into agent identities. Each tool becomes a
// permission; a tool whose name implies broad action (admin/delete/write-all)
// is flagged admin-equivalent so the over-privileged detector catches it too.
func Agents(data []byte) ([]model.Identity, error) {
	var in agentInventory
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}

	out := make([]model.Identity, 0, len(in.Agents))
	for _, a := range in.Agents {
		id := model.Identity{
			ID:         a.ID,
			Type:       model.IdentityAgent,
			Source:     "agents",
			Owner:      a.Owner,
			Runtime:    a.Runtime,
			OnBehalfOf: a.OnBehalfOf,
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
	return out, nil
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
