package detectors

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// spendEvent builds a tokenfuse spend-taxonomy event for id at an offset
// from fixedNow(), so callers can express "within the window" / "outside the
// window" declaratively.
func spendEvent(id string, typ model.EventType, ago time.Duration) model.Event {
	return model.Event{IdentityID: id, Type: typ, Time: fixedNow().Add(-ago)}
}

// fivePerms returns five distinctly-named, non-admin permissions — enough
// to cross blastRadiusThreshold on their own without also tripping the
// privileged/HasAdmin corroborating fact.
func fivePerms() []model.Permission {
	return []model.Permission{
		{Name: "tool:a"}, {Name: "tool:b"}, {Name: "tool:c"}, {Name: "tool:d"}, {Name: "tool:e"},
	}
}

// runawayAgentGraph builds one fixture covering every escalation branch of
// RunawayAgent plus the no-finding cases (no spend events at all; spend
// events entirely outside spendWindow; a non-agent identity that otherwise
// looks identical to a 0-fact agent).
func runawayAgentGraph() *graph.Store {
	g := graph.New(nil)

	// 0 corroborating facts: one spend event, no privilege, autonomous
	// (no OnBehalfOf), attested, small blast radius -> medium.
	g.AddIdentity(model.Identity{ID: "agent:zero-facts", Type: model.IdentityAgent, Attestation: "spiffe-svid"})
	g.AddEvent(spendEvent("agent:zero-facts", model.EventBudgetExhausted, time.Hour))

	// 1 corroborating fact (privileged only) -> still medium.
	g.AddIdentity(model.Identity{ID: "agent:one-fact-privileged", Type: model.IdentityAgent, Privileged: true, Attestation: "oidc"})
	g.AddEvent(spendEvent("agent:one-fact-privileged", model.EventSpendSpike, time.Hour))

	// 1 corroborating fact (blast radius only, via 5 non-admin permissions
	// on the identity itself) -> still medium. Isolates the blast-radius
	// branch from the privileged branch (HasAdmin must stay false).
	g.AddIdentity(model.Identity{ID: "agent:one-fact-blast", Type: model.IdentityAgent, Attestation: "oidc", Permissions: fivePerms()})
	g.AddEvent(spendEvent("agent:one-fact-blast", model.EventSustainedLoop, time.Hour))

	// 2 corroborating facts (privileged + delegation depth >= 1) -> high.
	g.AddIdentity(model.Identity{ID: "principal:two-facts", Type: model.IdentityServiceAccount})
	g.AddIdentity(model.Identity{
		ID: "agent:two-facts", Type: model.IdentityAgent, Privileged: true, Attestation: "mtls-cert",
		OnBehalfOf: []string{"principal:two-facts"},
	})
	g.AddEvent(spendEvent("agent:two-facts", model.EventFanoutExplosion, time.Hour))

	// 3 corroborating facts (privileged + delegation + unattested via empty
	// string) -> critical.
	g.AddIdentity(model.Identity{ID: "principal:three-facts", Type: model.IdentityServiceAccount})
	g.AddIdentity(model.Identity{
		ID: "agent:three-facts", Type: model.IdentityAgent, Privileged: true,
		OnBehalfOf: []string{"principal:three-facts"}, // Attestation left zero (unset)
	})
	g.AddEvent(spendEvent("agent:three-facts", model.EventBreakerTripped, time.Hour))

	// 4 corroborating facts (privileged + delegation + unattested "none" +
	// blast radius >= threshold) -> critical (confirms the mapping caps at
	// critical rather than something beyond it).
	g.AddIdentity(model.Identity{ID: "principal:four-facts", Type: model.IdentityServiceAccount})
	g.AddIdentity(model.Identity{
		ID: "agent:four-facts", Type: model.IdentityAgent, Privileged: true, Attestation: "none",
		OnBehalfOf: []string{"principal:four-facts"}, Permissions: fivePerms(),
	})
	g.AddEvent(spendEvent("agent:four-facts", model.EventBudgetExhausted, time.Hour))
	g.AddEvent(spendEvent("agent:four-facts", model.EventSpendSpike, 2*time.Hour))

	// No spend events at all (only an unrelated event type) -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:no-spend", Type: model.IdentityAgent, Privileged: true})
	g.AddEvent(model.Event{IdentityID: "agent:no-spend", Type: model.EventDLPBlock, Time: fixedNow().Add(-time.Hour)})

	// Spend events exist but are entirely outside spendWindow -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:stale-spend", Type: model.IdentityAgent, Privileged: true})
	g.AddEvent(spendEvent("agent:stale-spend", model.EventBudgetExhausted, 45*24*time.Hour))

	// A non-agent identity with an otherwise-identical spend event must
	// never be flagged: RunawayAgent is agent-only.
	g.AddIdentity(model.Identity{ID: "role:not-an-agent", Type: model.IdentityServiceAccount, Privileged: true})
	g.AddEvent(spendEvent("role:not-an-agent", model.EventBudgetExhausted, time.Hour))

	return g
}

func TestRunawayAgentSeverityEscalation(t *testing.T) {
	withFixedNow(t)
	got := detect(NewRunawayAgent(), runawayAgentGraph())

	cases := []struct {
		id   string
		want model.Severity
	}{
		{"agent:zero-facts", model.SeverityMedium},
		{"agent:one-fact-privileged", model.SeverityMedium},
		{"agent:one-fact-blast", model.SeverityMedium},
		{"agent:two-facts", model.SeverityHigh},
		{"agent:three-facts", model.SeverityCritical},
		{"agent:four-facts", model.SeverityCritical},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected a runaway_agent finding, got none", c.id)
			continue
		}
		if a.Severity != c.want {
			t.Errorf("%s: severity = %v, want %v (summary: %s)", c.id, a.Severity, c.want, a.Summary)
		}
	}
}

func TestRunawayAgentNoFindingCases(t *testing.T) {
	withFixedNow(t)
	got := detect(NewRunawayAgent(), runawayAgentGraph())

	for _, id := range []string{"agent:no-spend", "agent:stale-spend", "role:not-an-agent"} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no runaway_agent finding, got %+v", id, a)
		}
	}
}

// TestRunawayAgentOneFindingPerAgent pins the "one finding per agent, not
// per event" contract: agent:four-facts has two spend events in the fixture
// and must still produce exactly one alert.
func TestRunawayAgentOneFindingPerAgent(t *testing.T) {
	withFixedNow(t)
	alerts := NewRunawayAgent().Detect(runawayAgentGraph())
	count := 0
	for _, a := range alerts {
		if a.IdentityID == "agent:four-facts" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("agent:four-facts produced %d alerts, want exactly 1", count)
	}
}

// TestRunawayAgentSummaryContent spot-checks that the summary carries the
// event breakdown, chain depth, attestation state, and blast-radius summary
// the task requires, using the event counts and formatting are stable
// (formatEventCounts sorts by type name).
func TestRunawayAgentSummaryContent(t *testing.T) {
	withFixedNow(t)
	got := detect(NewRunawayAgent(), runawayAgentGraph())
	a, ok := got["agent:four-facts"]
	if !ok {
		t.Fatal("expected agent:four-facts to be flagged")
	}
	for _, want := range []string{
		"budget_exhausted=1", "spend_spike=1", // event breakdown
		"delegation depth 1", // chain
		"attestation=none",   // attestation state
		"blast radius 5",     // blast-radius summary
	} {
		if !strings.Contains(a.Summary, want) {
			t.Errorf("summary %q missing %q", a.Summary, want)
		}
	}
}

// TestRunawayAgentDeterministic runs Detect twice over the same graph and
// asserts an identical result — the detector must never depend on map
// iteration order or any other non-deterministic input.
func TestRunawayAgentDeterministic(t *testing.T) {
	withFixedNow(t)
	g := runawayAgentGraph()
	first := NewRunawayAgent().Detect(g)
	second := NewRunawayAgent().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
