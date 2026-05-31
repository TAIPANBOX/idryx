package main

import (
	"testing"
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
	g, err := buildGraph("", "", "", "", "", "", loads)
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
