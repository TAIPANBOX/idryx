package detectors

import (
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// mcpDriftGraph builds one fixture covering mcp_drift's single-occurrence
// trigger, count-based and privilege/admin escalation, and the no-finding
// cases (no event, stale outside the window, wrong event type, wrong
// identity kind).
func mcpDriftGraph() *graph.Store {
	g := graph.New(nil)

	// A single mcp_drift, unprivileged, non-admin -> high (a single
	// occurrence already fires; see the rationale in mcp_drift.go).
	g.AddIdentity(model.Identity{ID: "agent:single-drift", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:single-drift", model.EventMCPDrift, time.Hour))

	// Two mcp_drift events -> critical purely from the repeat count.
	g.AddIdentity(model.Identity{ID: "agent:repeat-drift", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:repeat-drift", model.EventMCPDrift, time.Hour))
	g.AddEvent(spendEvent("agent:repeat-drift", model.EventMCPDrift, 2*time.Hour))

	// A single mcp_drift but Privileged -> critical via the privilege
	// escalation, not the repeat-count escalation (isolates the two branches).
	g.AddIdentity(model.Identity{ID: "agent:privileged-single", Type: model.IdentityAgent, Privileged: true})
	g.AddEvent(spendEvent("agent:privileged-single", model.EventMCPDrift, time.Hour))

	// A single mcp_drift but HasAdmin via a permission (not the Privileged
	// flag) -> critical, isolating the HasAdmin() branch specifically.
	g.AddIdentity(model.Identity{
		ID: "agent:admin-single", Type: model.IdentityAgent,
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	g.AddEvent(spendEvent("agent:admin-single", model.EventMCPDrift, time.Hour))

	// No mcp_drift at all (only an unrelated event type) -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:no-drift", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:no-drift", model.EventDLPBlock, time.Hour))

	// An mcp_drift that is entirely outside mcpDriftWindow -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:stale-drift", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:stale-drift", model.EventMCPDrift, mcpDriftWindow+time.Hour))

	// A taint_block, not an mcp_drift -> no finding; confirms type-specific
	// filtering (tainted_agent's concern, not this detector's).
	g.AddIdentity(model.Identity{ID: "agent:wrong-event-type", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:wrong-event-type", model.EventTaintBlock, time.Hour))

	// An mcp_drift on a non-agent identity -> must never be flagged; this
	// detector is agent-only.
	g.AddIdentity(model.Identity{ID: "role:not-an-agent", Type: model.IdentityServiceAccount})
	g.AddEvent(spendEvent("role:not-an-agent", model.EventMCPDrift, time.Hour))

	return g
}

func TestMCPDrift(t *testing.T) {
	withFixedNow(t)
	got := detect(NewMCPDrift(), mcpDriftGraph())

	cases := []struct {
		id   string
		want model.Severity
	}{
		{"agent:single-drift", model.SeverityHigh},
		{"agent:repeat-drift", model.SeverityCritical},
		{"agent:privileged-single", model.SeverityCritical},
		{"agent:admin-single", model.SeverityCritical},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected an mcp_drift finding, got none", c.id)
			continue
		}
		if a.Severity != c.want {
			t.Errorf("%s: severity = %v, want %v (summary: %s)", c.id, a.Severity, c.want, a.Summary)
		}
	}
}

func TestMCPDriftNoFindingCases(t *testing.T) {
	withFixedNow(t)
	got := detect(NewMCPDrift(), mcpDriftGraph())

	for _, id := range []string{
		"agent:no-drift",
		"agent:stale-drift",
		"agent:wrong-event-type",
		"role:not-an-agent",
	} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no mcp_drift finding, got %+v", id, a)
		}
	}
}

// TestMCPDriftDeterministic mirrors runaway_agent's determinism check: same
// graph, two Detect calls, identical output.
func TestMCPDriftDeterministic(t *testing.T) {
	withFixedNow(t)
	g := mcpDriftGraph()
	first := NewMCPDrift().Detect(g)
	second := NewMCPDrift().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
