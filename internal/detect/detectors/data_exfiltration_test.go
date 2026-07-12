package detectors

import (
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// dataExfiltrationGraph builds one fixture covering data_exfiltration's
// threshold, count-based escalation, privilege/admin escalation, and the
// no-finding cases (below threshold, stale outside the window, wrong event
// type, wrong identity kind).
func dataExfiltrationGraph() *graph.Store {
	g := graph.New(nil)

	// Exactly at the threshold (3), unprivileged, non-admin -> high.
	g.AddIdentity(model.Identity{ID: "agent:at-threshold", Type: model.IdentityAgent})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("agent:at-threshold", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	// At double the threshold (6) -> critical purely from count.
	g.AddIdentity(model.Identity{ID: "agent:double-threshold", Type: model.IdentityAgent})
	for i := 0; i < dlpBlockThreshold*2; i++ {
		g.AddEvent(spendEvent("agent:double-threshold", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	// At the threshold but Privileged -> critical via the privilege escalation,
	// not the count escalation (isolates the two branches).
	g.AddIdentity(model.Identity{ID: "agent:privileged-at-threshold", Type: model.IdentityAgent, Privileged: true})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("agent:privileged-at-threshold", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	// At the threshold but HasAdmin via a permission (not the Privileged
	// flag) -> critical, isolating the HasAdmin() branch specifically.
	g.AddIdentity(model.Identity{
		ID: "agent:admin-at-threshold", Type: model.IdentityAgent,
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("agent:admin-at-threshold", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	// One below the threshold -> no finding (a lone/couple of blocks is noise).
	g.AddIdentity(model.Identity{ID: "agent:below-threshold", Type: model.IdentityAgent})
	for i := 0; i < dlpBlockThreshold-1; i++ {
		g.AddEvent(spendEvent("agent:below-threshold", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	// At-threshold count, but every event is outside dlpBlockWindow -> no
	// finding (stale blocks are not a live episode).
	g.AddIdentity(model.Identity{ID: "agent:stale-blocks", Type: model.IdentityAgent})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("agent:stale-blocks", model.EventDLPBlock, dlpBlockWindow+time.Duration(i+1)*time.Hour))
	}

	// At-threshold count of a different event type (taint_block, not
	// dlp_block) -> no finding; confirms type-specific filtering.
	g.AddIdentity(model.Identity{ID: "agent:wrong-event-type", Type: model.IdentityAgent})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("agent:wrong-event-type", model.EventTaintBlock, time.Duration(i+1)*time.Hour))
	}

	// At-threshold count on a non-agent identity -> must never be flagged;
	// this detector is agent-only.
	g.AddIdentity(model.Identity{ID: "role:not-an-agent", Type: model.IdentityServiceAccount})
	for i := 0; i < dlpBlockThreshold; i++ {
		g.AddEvent(spendEvent("role:not-an-agent", model.EventDLPBlock, time.Duration(i+1)*time.Hour))
	}

	return g
}

func TestDataExfiltration(t *testing.T) {
	withFixedNow(t)
	got := detect(NewDataExfiltration(), dataExfiltrationGraph())

	cases := []struct {
		id   string
		want model.Severity
	}{
		{"agent:at-threshold", model.SeverityHigh},
		{"agent:double-threshold", model.SeverityCritical},
		{"agent:privileged-at-threshold", model.SeverityCritical},
		{"agent:admin-at-threshold", model.SeverityCritical},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected a data_exfiltration finding, got none", c.id)
			continue
		}
		if a.Severity != c.want {
			t.Errorf("%s: severity = %v, want %v (summary: %s)", c.id, a.Severity, c.want, a.Summary)
		}
	}
}

func TestDataExfiltrationNoFindingCases(t *testing.T) {
	withFixedNow(t)
	got := detect(NewDataExfiltration(), dataExfiltrationGraph())

	for _, id := range []string{
		"agent:below-threshold",
		"agent:stale-blocks",
		"agent:wrong-event-type",
		"role:not-an-agent",
	} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no data_exfiltration finding, got %+v", id, a)
		}
	}
}

// TestDataExfiltrationDeterministic mirrors runaway_agent's determinism
// check: same graph, two Detect calls, identical output.
func TestDataExfiltrationDeterministic(t *testing.T) {
	withFixedNow(t)
	g := dataExfiltrationGraph()
	first := NewDataExfiltration().Detect(g)
	second := NewDataExfiltration().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
