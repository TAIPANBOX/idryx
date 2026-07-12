package detectors

import (
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// taintedAgentGraph builds one fixture covering tainted_agent's
// single-occurrence trigger, count-based and privilege/admin escalation, and
// the no-finding cases (no event, stale outside the window, wrong event
// type, wrong identity kind).
func taintedAgentGraph() *graph.Store {
	g := graph.New(nil)

	// A single taint_block, unprivileged, non-admin -> high (a single
	// occurrence already fires; see the rationale in tainted_agent.go).
	g.AddIdentity(model.Identity{ID: "agent:single-block", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:single-block", model.EventTaintBlock, time.Hour))

	// Two taint_block events -> critical purely from the repeat count.
	g.AddIdentity(model.Identity{ID: "agent:repeat-block", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:repeat-block", model.EventTaintBlock, time.Hour))
	g.AddEvent(spendEvent("agent:repeat-block", model.EventTaintBlock, 2*time.Hour))

	// A single taint_block but Privileged -> critical via the privilege
	// escalation, not the repeat-count escalation (isolates the two branches).
	g.AddIdentity(model.Identity{ID: "agent:privileged-single", Type: model.IdentityAgent, Privileged: true})
	g.AddEvent(spendEvent("agent:privileged-single", model.EventTaintBlock, time.Hour))

	// A single taint_block but HasAdmin via a permission (not the Privileged
	// flag) -> critical, isolating the HasAdmin() branch specifically.
	g.AddIdentity(model.Identity{
		ID: "agent:admin-single", Type: model.IdentityAgent,
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	g.AddEvent(spendEvent("agent:admin-single", model.EventTaintBlock, time.Hour))

	// No taint_block at all (only an unrelated event type) -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:no-block", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:no-block", model.EventDLPBlock, time.Hour))

	// A taint_block that is entirely outside taintBlockWindow -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:stale-block", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:stale-block", model.EventTaintBlock, taintBlockWindow+time.Hour))

	// A dlp_block, not a taint_block -> no finding; confirms type-specific
	// filtering (data_exfiltration's concern, not this detector's).
	g.AddIdentity(model.Identity{ID: "agent:wrong-event-type", Type: model.IdentityAgent})
	g.AddEvent(spendEvent("agent:wrong-event-type", model.EventDLPBlock, time.Hour))

	// A taint_block on a non-agent identity -> must never be flagged; this
	// detector is agent-only.
	g.AddIdentity(model.Identity{ID: "role:not-an-agent", Type: model.IdentityServiceAccount})
	g.AddEvent(spendEvent("role:not-an-agent", model.EventTaintBlock, time.Hour))

	return g
}

func TestTaintedAgent(t *testing.T) {
	withFixedNow(t)
	got := detect(NewTaintedAgent(), taintedAgentGraph())

	cases := []struct {
		id   string
		want model.Severity
	}{
		{"agent:single-block", model.SeverityHigh},
		{"agent:repeat-block", model.SeverityCritical},
		{"agent:privileged-single", model.SeverityCritical},
		{"agent:admin-single", model.SeverityCritical},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected a tainted_agent finding, got none", c.id)
			continue
		}
		if a.Severity != c.want {
			t.Errorf("%s: severity = %v, want %v (summary: %s)", c.id, a.Severity, c.want, a.Summary)
		}
	}
}

func TestTaintedAgentNoFindingCases(t *testing.T) {
	withFixedNow(t)
	got := detect(NewTaintedAgent(), taintedAgentGraph())

	for _, id := range []string{
		"agent:no-block",
		"agent:stale-block",
		"agent:wrong-event-type",
		"role:not-an-agent",
	} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no tainted_agent finding, got %+v", id, a)
		}
	}
}

// TestTaintedAgentDeterministic mirrors runaway_agent's determinism check:
// same graph, two Detect calls, identical output.
func TestTaintedAgentDeterministic(t *testing.T) {
	withFixedNow(t)
	g := taintedAgentGraph()
	first := NewTaintedAgent().Detect(g)
	second := NewTaintedAgent().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
