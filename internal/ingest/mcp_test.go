package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestMCP(t *testing.T) {
	data := []byte(`{
	  "registry": ["github-mcp", "jira-mcp"],
	  "servers": [
	    {"name":"github-mcp","url":"https://mcp.internal/github","owner":"platform","tools":["repo_read","repo_write"]},
	    {"name":"evil-mcp","url":"https://mcp.evil.example/x","tools":["shell_exec"]},
	    {"name":"jira-mcp","url":"https://mcp.internal/jira","tools":["issue_read"]},
	    {"name":"legacy-mcp","url":"https://mcp.internal/legacy","sanctioned":true,"tools":["ticket_read"]}
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

	gh := byID["mcp:github-mcp@https://mcp.internal/github"]
	if gh.Type != model.IdentityMCPServer || gh.Source != "mcp" {
		t.Errorf("github-mcp type/source = %v/%q", gh.Type, gh.Source)
	}
	if gh.Shadow {
		t.Error("github-mcp is in the registry; must not be shadow")
	}

	evil := byID["mcp:evil-mcp@https://mcp.evil.example/x"]
	if !evil.Shadow {
		t.Error("evil-mcp is absent from registry; must be shadow")
	}
	if !evil.HasAdmin() || !evil.Privileged {
		t.Error("evil-mcp exposes shell_exec; should be admin/privileged")
	}

	if byID["mcp:jira-mcp@https://mcp.internal/jira"].Shadow {
		t.Error("jira-mcp is in the registry; must not be shadow")
	}
	// Explicit sanctioned override wins over registry absence.
	if byID["mcp:legacy-mcp@https://mcp.internal/legacy"].Shadow {
		t.Error("legacy-mcp is explicitly sanctioned; must not be shadow")
	}
}

// TestMCPSameNameDistinctURLsDoNotCollide is the regression test for the ID
// collision bug: two MCP servers that share a display Name (e.g. two teams
// both calling theirs "internal-tools") must still get distinct graph
// identities when their URLs differ, and merging them into one graph must
// not let the shadow (unsanctioned) server's flag or tools contaminate the
// sanctioned one. Before the fix, both identities were keyed "mcp:"+Name
// alone, so they collapsed onto the same graph node: Shadow is a sticky OR
// in Store.AddIdentity, so the sanctioned server's legit tool would get
// mislabeled shadow, and permissions from both servers would concatenate
// onto one node.
func TestMCPSameNameDistinctURLsDoNotCollide(t *testing.T) {
	data := []byte(`{
	  "registry": [],
	  "servers": [
	    {"name":"internal-tools","url":"https://team-a.example/mcp","owner":"team-a","sanctioned":true,"tools":["repo_read"]},
	    {"name":"internal-tools","url":"https://team-b.example/mcp","owner":"team-b","sanctioned":false,"tools":["shell_exec"]}
	  ]
	}`)

	ids, err := MCP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	if ids[0].ID == ids[1].ID {
		t.Fatalf("same-name servers with different URLs got the same ID %q; distinct servers must not collapse", ids[0].ID)
	}

	var sanctioned, shadow *model.Identity
	for i := range ids {
		switch ids[i].Owner {
		case "team-a":
			sanctioned = &ids[i]
		case "team-b":
			shadow = &ids[i]
		}
	}
	if sanctioned == nil || shadow == nil {
		t.Fatalf("expected one identity per owner, got %+v", ids)
	}
	if sanctioned.Shadow {
		t.Error("team-a's server is explicitly sanctioned; must not be shadow")
	}
	if !shadow.Shadow {
		t.Error("team-b's server is explicitly unsanctioned; must be shadow")
	}

	// End-to-end: feed both into the graph the way the CLI does
	// (populate -> g.AddIdentity per parsed identity) and confirm they stay
	// two distinct nodes with no cross-contamination of Shadow or tools.
	g := graph.New(nil)
	for _, id := range ids {
		g.AddIdentity(id)
	}
	graphIDs := g.Identities()
	if len(graphIDs) != 2 {
		t.Fatalf("graph collapsed same-name servers into %d node(s), want 2", len(graphIDs))
	}
	for _, node := range graphIDs {
		switch node.Owner {
		case "team-a":
			if node.Shadow {
				t.Error("sanctioned team-a node became shadow after merging into the graph (contamination)")
			}
			if node.HasAdmin() {
				t.Error("sanctioned team-a node picked up team-b's high-risk tool (permission contamination)")
			}
		case "team-b":
			if !node.Shadow {
				t.Error("unsanctioned team-b node lost its shadow flag after merging into the graph")
			}
		default:
			t.Errorf("unexpected node in graph: %+v", node)
		}
	}
}
