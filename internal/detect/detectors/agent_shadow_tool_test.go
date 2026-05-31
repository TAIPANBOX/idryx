package detectors

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func agentShadowGraph() *graph.Store {
	g := graph.New(nil)
	// Shadow MCP server exposing a high-risk tool and a benign one.
	g.AddIdentity(model.Identity{
		ID: "mcp:rogue", Type: model.IdentityMCPServer, Source: "mcp", Shadow: true,
		Permissions: []model.Permission{
			{Name: "shell_exec", Admin: true},
			{Name: "notes_read"},
		},
	})
	// Sanctioned MCP server (not shadow): its tools must not trigger anything.
	g.AddIdentity(model.Identity{
		ID: "mcp:github", Type: model.IdentityMCPServer, Source: "mcp",
		Permissions: []model.Permission{{Name: "repo_read"}},
	})
	// Agent wired to the rogue server's high-risk tool -> critical.
	g.AddIdentity(model.Identity{
		ID: "agent:builder", Type: model.IdentityAgent, Source: "agents",
		Permissions: []model.Permission{{Name: "shell_exec", Admin: true}, {Name: "repo_read"}},
	})
	// Agent wired to the rogue server's benign tool only -> high.
	g.AddIdentity(model.Identity{
		ID: "agent:notetaker", Type: model.IdentityAgent, Source: "agents",
		Permissions: []model.Permission{{Name: "notes_read"}},
	})
	// Agent using only sanctioned tools -> no alert.
	g.AddIdentity(model.Identity{
		ID: "agent:reader", Type: model.IdentityAgent, Source: "agents",
		Permissions: []model.Permission{{Name: "repo_read"}},
	})
	return g
}

func TestAgentShadowTool(t *testing.T) {
	withFixedNow(t)
	got := detect(NewAgentShadowTool(), agentShadowGraph())

	if a, ok := got["agent:builder"]; !ok {
		t.Error("expected alert for agent:builder")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("agent:builder severity = %v, want critical", a.Severity)
	}

	if a, ok := got["agent:notetaker"]; !ok {
		t.Error("expected alert for agent:notetaker")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("agent:notetaker severity = %v, want high", a.Severity)
	}

	if _, ok := got["agent:reader"]; ok {
		t.Error("agent:reader uses only sanctioned tools; should not alert")
	}
	if _, ok := got["mcp:rogue"]; ok {
		t.Error("the MCP server itself is shadow_mcp's concern, not agent_shadow_tool")
	}
}

func TestAgentShadowToolNoShadow(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "agent:x", Type: model.IdentityAgent, Source: "agents",
		Permissions: []model.Permission{{Name: "shell_exec"}},
	})
	if got := detect(NewAgentShadowTool(), g); len(got) != 0 {
		t.Errorf("no shadow MCP servers present; expected no alerts, got %v", got)
	}
}
