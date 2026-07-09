package main

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestMultiSourceStitchesAgentAndMCP is the regression test for the cross-layer
// gap: agent_shadow_tool can only fire when agents and mcp live in one graph.
// The CLI loads one source per file, so --load must stitch several sources
// together. This builds that combined graph and asserts the detector fires for
// the agent wired to a shadow MCP tool, and stays silent for clean agents.
func TestMultiSourceStitchesAgentAndMCP(t *testing.T) {
	loads := loadList{
		{Source: "agents", Path: "../../testdata/demo_agents.json"},
		{Source: "mcp", Path: "../../testdata/demo_mcp.json"},
	}
	g, err := buildGraph("", "", "", "", "", "", "", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	alerts := runDetectors(g)
	got := map[string]string{} // identity -> severity, for agent_shadow_tool only
	for _, a := range alerts {
		if a.Detector == "agent_shadow_tool" {
			got[a.IdentityID] = a.Severity.String()
		}
	}

	// ops-helper uses shell_exec (high-risk) from the rogue-shell shadow server.
	if sev, ok := got["agent:ops-helper"]; !ok {
		t.Error("expected agent:ops-helper to be flagged by agent_shadow_tool")
	} else if sev != "critical" {
		t.Errorf("agent:ops-helper severity = %q, want critical (high-risk tool)", sev)
	}

	// notetaker uses note_fetch from rogue-notes (not high-risk) -> high.
	if sev, ok := got["agent:notetaker"]; !ok {
		t.Error("expected agent:notetaker to be flagged by agent_shadow_tool")
	} else if sev != "high" {
		t.Errorf("agent:notetaker severity = %q, want high", sev)
	}

	// clean-bot only uses sanctioned github-mcp tools -> must not be flagged.
	if _, ok := got["agent:clean-bot"]; ok {
		t.Error("agent:clean-bot uses only sanctioned tools; must not be flagged")
	}
}

func TestLoadListSet(t *testing.T) {
	var l loadList
	if err := l.Set("agents:a.json"); err != nil {
		t.Fatal(err)
	}
	if err := l.Set("mcp:m.json"); err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[0].Source != "agents" || l[0].Path != "a.json" || l[1].Source != "mcp" {
		t.Errorf("unexpected loadList: %+v", l)
	}
	if err := l.Set("bogus"); err == nil {
		t.Error("expected error for missing colon")
	}
	if err := l.Set(":nopath"); err == nil {
		t.Error("expected error for empty source")
	}
}

// TestLoadTokenFuseStitchesIdentitiesAndEvents is the CLI-level wiring check
// for the tokenfuse connector (agent-passport SPEC §6.3): --load tokenfuse:path
// must populate the graph with both the agent/human identities and the
// behavioral events from the same NDJSON file, and the delegation chain
// carried in on_behalf_of must survive into the graph unchanged.
func TestLoadTokenFuseStitchesIdentitiesAndEvents(t *testing.T) {
	loads := loadList{
		{Source: "tokenfuse", Path: "../../testdata/tokenfuse.ndjson"},
	}
	g, err := buildGraph("", "", "", "", "", "", "", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	ids := g.Identities()
	if len(ids) != 4 {
		t.Fatalf("got %d identities, want 4 (2 agents seen directly + 1 sub-agent + 1 human)", len(ids))
	}

	var sub *model.Identity
	var totalEvents int
	for _, id := range ids {
		totalEvents += len(id.Events)
		if id.ID == "agent://acme-bank.example/support/sub-agent" {
			sub = id
		}
	}
	if totalEvents != 10 {
		t.Errorf("total events across the graph = %d, want 10", totalEvents)
	}
	if sub == nil {
		t.Fatal("expected agent://acme-bank.example/support/sub-agent in the graph")
	}
	wantChain := []string{"user://acme-bank.example/j.doe", "agent://acme-bank.example/support/orchestrator"}
	if len(sub.OnBehalfOf) != len(wantChain) {
		t.Fatalf("sub-agent chain = %v, want %v", sub.OnBehalfOf, wantChain)
	}
	for i := range wantChain {
		if sub.OnBehalfOf[i] != wantChain[i] {
			t.Errorf("sub-agent chain[%d] = %q, want %q", i, sub.OnBehalfOf[i], wantChain[i])
		}
	}
}

// TestBuildGraphLayersPassports is the CLI-level wiring check for
// --passports: it enriches an identity already produced by another source
// (here, an agent tokenfuse also observed) with static Passport metadata,
// and adds an identity that exists only as a Passport (no behavioral events
// at all) as its own agent identity.
func TestBuildGraphLayersPassports(t *testing.T) {
	loads := loadList{
		{Source: "tokenfuse", Path: "../../testdata/tokenfuse.ndjson"},
	}
	g, err := buildGraph("", "", "", "", "", "", "../../testdata/passports", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	byID := map[string]*model.Identity{}
	for _, id := range g.Identities() {
		byID[id.ID] = id
	}

	tier1 := byID["agent://acme-bank.example/support/tier1-bot"]
	if tier1 == nil {
		t.Fatal("expected tier1-bot (from tokenfuse) in the graph")
	}
	if tier1.Attestation != "spiffe-svid" {
		t.Errorf("tier1-bot Attestation = %q, want spiffe-svid (from passport)", tier1.Attestation)
	}
	if tier1.Parent != "agent://acme-bank.example/support/orchestrator" {
		t.Errorf("tier1-bot Parent = %q, want agent://acme-bank.example/support/orchestrator", tier1.Parent)
	}
	if len(tier1.Events) == 0 {
		t.Error("tier1-bot should keep its tokenfuse events after passport enrichment merges in")
	}

	standalone := byID["agent://acme-bank.example/eng/standalone"]
	if standalone == nil {
		t.Fatal("expected standalone (passport-only) agent in the graph")
	}
	if standalone.Attestation != "none" {
		t.Errorf("standalone Attestation = %q, want none", standalone.Attestation)
	}
	if standalone.Type != model.IdentityAgent {
		t.Errorf("standalone Type = %q, want agent", standalone.Type)
	}
}
