package ingest

import (
	"encoding/json"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// mcpInventory is the input idryx reads for the mcp source: the sanctioned MCP
// server registry plus the servers actually observed in the environment. A
// server seen in use but missing from the registry is shadow MCP (OWASP MCP Top
// 10: Shadow MCP Servers). Each server's exposed tools become permissions, so
// the over-privileged and tool-poisoning surface is visible in the same graph.
type mcpInventory struct {
	Registry []string    `json:"registry"` // sanctioned server names
	Servers  []mcpServer `json:"servers"`
}

type mcpServer struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Owner      string   `json:"owner"`
	Sanctioned *bool    `json:"sanctioned"` // explicit override; else derived from registry
	Tools      []string `json:"tools"`      // tool/scope names the server exposes
}

// MCP parses the MCP inventory into mcp_server identities. A server is shadow
// when it is neither listed in the registry nor explicitly sanctioned. A tool
// whose name implies broad or destructive action is flagged admin-equivalent,
// surfacing tool-poisoning risk to the over-privileged and shadow_mcp detectors.
func MCP(data []byte) ([]model.Identity, error) {
	var in mcpInventory
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}

	registry := make(map[string]bool, len(in.Registry))
	for _, r := range in.Registry {
		registry[r] = true
	}

	out := make([]model.Identity, 0, len(in.Servers))
	for _, s := range in.Servers {
		sanctioned := registry[s.Name]
		if s.Sanctioned != nil {
			sanctioned = *s.Sanctioned
		}
		id := model.Identity{
			// Keyed by Name+URL, not Name alone: two servers can share a
			// display Name (e.g. two teams both calling theirs
			// "internal-tools"), and keying on Name alone collapsed them
			// onto one graph node, so Shadow (a sticky OR in
			// Store.AddIdentity) and permissions from an unsanctioned
			// server leaked onto a sanctioned one sharing its name.
			ID:     "mcp:" + s.Name + "@" + s.URL,
			Type:   model.IdentityMCPServer,
			Source: "mcp",
			Owner:  s.Owner,
			Shadow: !sanctioned,
		}
		for _, tool := range s.Tools {
			id.Permissions = append(id.Permissions, model.Permission{
				Name:  tool,
				Admin: isHighRiskTool(tool),
			})
		}
		id.Privileged = id.HasAdmin()
		out = append(out, id)
	}
	return out, nil
}
