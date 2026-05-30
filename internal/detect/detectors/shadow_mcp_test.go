package detectors

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func mcpGraph() *graph.Store {
	g := graph.New(nil)
	// shadow + high-risk tool -> critical
	g.AddIdentity(model.Identity{
		ID: "mcp:evil", Type: model.IdentityMCPServer, Source: "mcp", Shadow: true,
		Permissions: []model.Permission{{Name: "shell_exec", Admin: true}},
	})
	// shadow + benign tools -> high
	g.AddIdentity(model.Identity{
		ID: "mcp:rogue", Type: model.IdentityMCPServer, Source: "mcp", Shadow: true,
		Permissions: []model.Permission{{Name: "notes_read"}},
	})
	// sanctioned -> nothing, even with an admin tool
	g.AddIdentity(model.Identity{
		ID: "mcp:github", Type: model.IdentityMCPServer, Source: "mcp", Shadow: false,
		Permissions: []model.Permission{{Name: "repo_admin", Admin: true}},
	})
	// non-MCP NHI -> ignored
	g.AddIdentity(model.Identity{ID: "arn:role/x", Type: model.IdentityServiceAccount, Source: "aws_iam", Shadow: true})
	return g
}

func TestShadowMCP(t *testing.T) {
	withFixedNow(t)
	got := detect(NewShadowMCP(), mcpGraph())

	if a, ok := got["mcp:evil"]; !ok {
		t.Error("shadow MCP with high-risk tool should be flagged")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("evil severity = %v, want critical", a.Severity)
	}
	if a, ok := got["mcp:rogue"]; !ok {
		t.Error("shadow MCP should be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("rogue severity = %v, want high", a.Severity)
	}
	if _, ok := got["mcp:github"]; ok {
		t.Error("sanctioned MCP server must not be flagged")
	}
	if _, ok := got["arn:role/x"]; ok {
		t.Error("non-MCP identity must not be flagged by shadow_mcp")
	}
}
