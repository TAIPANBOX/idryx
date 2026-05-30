package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestMCP(t *testing.T) {
	data := []byte(`{
	  "registry": ["github-mcp", "jira-mcp"],
	  "servers": [
	    {"name":"github-mcp","owner":"platform","tools":["repo_read","repo_write"]},
	    {"name":"evil-mcp","tools":["shell_exec"]},
	    {"name":"jira-mcp","tools":["issue_read"]},
	    {"name":"legacy-mcp","sanctioned":true,"tools":["ticket_read"]}
	  ]
	}`)

	ids, err := MCP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 {
		t.Fatalf("got %d identities, want 4", len(ids))
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	gh := byID["mcp:github-mcp"]
	if gh.Type != model.IdentityMCPServer || gh.Source != "mcp" {
		t.Errorf("github-mcp type/source = %v/%q", gh.Type, gh.Source)
	}
	if gh.Shadow {
		t.Error("github-mcp is in the registry; must not be shadow")
	}

	evil := byID["mcp:evil-mcp"]
	if !evil.Shadow {
		t.Error("evil-mcp is absent from registry; must be shadow")
	}
	if !evil.HasAdmin() || !evil.Privileged {
		t.Error("evil-mcp exposes shell_exec; should be admin/privileged")
	}

	if byID["mcp:jira-mcp"].Shadow {
		t.Error("jira-mcp is in the registry; must not be shadow")
	}
	// Explicit sanctioned override wins over registry absence.
	if byID["mcp:legacy-mcp"].Shadow {
		t.Error("legacy-mcp is explicitly sanctioned; must not be shadow")
	}
}
