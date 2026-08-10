package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// busEvidence is what makes this detector willing to judge anything: some
// agent-event producer fed this graph. Only the bus connector sets
// Event.Source, so a non-empty one is its fingerprint.
func busEvidence(g *graph.Store, agent string) {
	g.AddEvent(model.Event{
		IdentityID: agent,
		Type:       model.EventSpendSpike,
		Source:     "tokenfuse",
		Severity:   "high",
		Time:       fixedNow(),
	})
}

// declaredAgent is an established identity whose Passport declares a binding.
func declaredAgent(g *graph.Store, name, method string, privileged bool) {
	g.AddIdentity(model.Identity{
		ID:          name,
		Type:        model.IdentityAgent,
		Source:      "passport",
		Attestation: method,
		Privileged:  privileged,
	})
}

// sensorSawClaim is what the eBPF sensor records when a process names itself.
func sensorSawClaim(g *graph.Store, agent string, n int) {
	for i := 0; i < n; i++ {
		g.AddEvent(model.Event{
			IdentityID: "claimed:" + agent,
			Type:       model.EventEgress,
			Outcome:    "SUCCESS",
			Resource:   "203.0.113.7:443",
			Time:       fixedNow().Add(time.Duration(i) * time.Second),
		})
	}
}

// The case the detector exists for: the organisation declared a binding, and
// the only runtime carrier of that name is a process that named itself.
func TestAnAgentWhoseOnlyCarrierIsAClaimIsFlagged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	busEvidence(g, "agent://acme.example/other-bot") // some bus producer feeds this graph
	declaredAgent(g, "agent://acme.example/planner", "spiffe-svid", false)
	sensorSawClaim(g, "agent://acme.example/planner", 3)

	a, ok := detect(NewClaimedAgentUnattested(), g)["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatal("expected a finding, got none")
	}
	if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium", a.Severity)
	}
	for _, want := range []string{"spiffe-svid", "observed 3 time(s)", "claiming to be"} {
		if !strings.Contains(a.Summary, want) {
			t.Errorf("the summary must carry %q, got: %s", want, a.Summary)
		}
	}
	// Both readings stay open, which is what the claim family is worded around.
	if !strings.Contains(a.Summary, "Either") {
		t.Errorf("the summary closes a reading it cannot close: %s", a.Summary)
	}
}

// A privileged agent in the same position is worse, the same way
// attestation_missing treats the same posture.
func TestAPrivilegedAgentInThatPositionIsHigh(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	busEvidence(g, "agent://acme.example/other-bot")
	declaredAgent(g, "agent://acme.example/planner", "mtls-cert", true)
	sensorSawClaim(g, "agent://acme.example/planner", 1)

	a := detect(NewClaimedAgentUnattested(), g)["claimed:agent://acme.example/planner"]
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high for a privileged agent", a.Severity)
	}
}

// Something other than the process itself has spoken about this agent. That is
// NOT proof the declared method was exercised, and it is enough: the name is
// carried by more than a self-declaration.
func TestAnAgentSomeProducerHasSpokenAboutIsSilent(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	declaredAgent(g, "agent://acme.example/planner", "spiffe-svid", false)
	busEvidence(g, "agent://acme.example/planner") // the established node carries an event
	sensorSawClaim(g, "agent://acme.example/planner", 2)

	if got := NewClaimedAgentUnattested().Detect(g); len(got) != 0 {
		t.Errorf("want silence when a producer has established this agent, got %d: %+v", len(got), got)
	}
}

// An agent that declares no binding has declared nothing to be at odds with.
// That posture is attestation_missing's and bom_incomplete's, and reporting it
// here would be one fact under a second name.
func TestAnAgentDeclaringNoBindingIsNotThisDetectorsFinding(t *testing.T) {
	withFixedNow(t)
	for _, method := range []string{"", "none"} {
		g := graph.New(nil)
		busEvidence(g, "agent://acme.example/other-bot")
		declaredAgent(g, "agent://acme.example/planner", method, false)
		sensorSawClaim(g, "agent://acme.example/planner", 2)

		if got := NewClaimedAgentUnattested().Detect(g); len(got) != 0 {
			t.Errorf("attestation=%q produced %d finding(s); that posture belongs to attestation_missing", method, len(got))
		}
	}
}

// The precondition. Without any bus producer in the graph, "nothing established
// this agent" is true of every agent in every sensor-only run, and means only
// that no bus file was loaded.
func TestWithNoBusProducerInTheGraphNothingIsJudged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	declaredAgent(g, "agent://acme.example/planner", "spiffe-svid", false)
	sensorSawClaim(g, "agent://acme.example/planner", 5)

	if got := NewClaimedAgentUnattested().Detect(g); len(got) != 0 {
		t.Errorf("want silence with no bus producer feeding the graph, got %d: %+v", len(got), got)
	}
}

// A claim naming an agent nobody declared is claimed_agent_unknown's finding.
// Firing here too would report one fact twice under two names.
func TestAClaimWithNoDeclaredAgentIsTheOtherDetectorsFinding(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	busEvidence(g, "agent://acme.example/other-bot")
	sensorSawClaim(g, "agent://acme.example/ghost", 2)

	if got := NewClaimedAgentUnattested().Detect(g); len(got) != 0 {
		t.Errorf("an unresolved claim is claimed_agent_unknown's, got %d finding(s)", len(got))
	}
}

// Determinism, invariant 1: the same graph produces the same findings in the
// same order.
func TestTheUnattestedFindingsAreDeterministic(t *testing.T) {
	withFixedNow(t)
	build := func() *graph.Store {
		g := graph.New(nil)
		busEvidence(g, "agent://acme.example/other-bot")
		declaredAgent(g, "agent://acme.example/planner", "spiffe-svid", false)
		declaredAgent(g, "agent://acme.example/auditor", "oidc", false)
		sensorSawClaim(g, "agent://acme.example/planner", 2)
		sensorSawClaim(g, "agent://acme.example/auditor", 1)
		return g
	}
	first := NewClaimedAgentUnattested().Detect(build())
	if len(first) != 2 {
		t.Fatalf("want two findings, got %d", len(first))
	}
	for i := 0; i < 5; i++ {
		again := NewClaimedAgentUnattested().Detect(build())
		for j := range first {
			if again[j].IdentityID != first[j].IdentityID || again[j].Summary != first[j].Summary {
				t.Fatalf("run %d differs at %d:\n first: %s\n again: %s", i, j, first[j].Summary, again[j].Summary)
			}
		}
	}
}
