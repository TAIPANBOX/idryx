package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// governedBy adds the enforcement point's own journal for one agent: n fetches
// it performed, and refused of them refusals. This is the established
// namespace, the subject the plane derived from an authenticated credential.
func governedBy(g *graph.Store, agent string, fetches, refused int) {
	for i := 0; i < fetches; i++ {
		g.AddEvent(model.Event{
			IdentityID: agent,
			Type:       model.EventWebFetch,
			Source:     EnforcementSource,
			Severity:   "low",
			Time:       fixedNow().Add(time.Duration(i) * time.Minute),
		})
	}
	for i := 0; i < refused; i++ {
		g.AddEvent(model.Event{
			IdentityID: agent,
			Type:       model.EventWebBlocked,
			Source:     EnforcementSource,
			Severity:   "high",
			Time:       fixedNow().Add(time.Duration(100+i) * time.Minute),
		})
	}
}

// sensorSaw adds what the eBPF sensor observed under the identity a process
// claimed for itself (AGENT_PASSPORT_ID, SPEC 3.3).
func sensorSaw(g *graph.Store, agent string, destinations ...string) {
	for i, dest := range destinations {
		g.AddEvent(model.Event{
			IdentityID: "claimed:" + agent,
			Type:       model.EventEgress,
			Outcome:    "SUCCESS",
			Resource:   dest,
			Time:       fixedNow().Add(time.Duration(i) * time.Second),
		})
	}
}

// The case the detector exists for: the plane governs this agent, and the
// sensor watched its process open its own connection to the public internet.
// A governed fetch is performed by the enforcement point's process, so this one
// cannot have been governed.
func TestAGovernedAgentReachingAPublicAddressDirectlyIsFlagged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 3, 0)
	sensorSaw(g, "agent://acme.example/planner", "203.0.113.7:443")

	got := detect(NewUnroutedEgress(), g)
	a, ok := got["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatalf("expected a finding, got none: %v", got)
	}
	if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium", a.Severity)
	}
	if !strings.Contains(a.Summary, "203.0.113.7") {
		t.Errorf("the finding must name what was reached, got: %s", a.Summary)
	}
	if !strings.Contains(a.Summary, "3 journal event(s)") {
		t.Errorf("the finding must say what proves the agent is governed, got: %s", a.Summary)
	}
}

// A plane that already said no, and traffic that went around it, is a
// different fact from traffic that never asked. This is the only deterministic
// pattern in this data that no other detector can produce.
func TestARefusalFollowedByADirectConnectionIsHigh(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 2, 1)
	sensorSaw(g, "agent://acme.example/planner", "203.0.113.7:443")

	a, ok := detect(NewUnroutedEgress(), g)["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatal("expected a finding, got none")
	}
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high: the plane refused this agent and it went直 around", a.Severity)
	}
	if !strings.Contains(a.Summary, "refused") {
		t.Errorf("the finding must say the plane had already refused it, got: %s", a.Summary)
	}
}

// The first precondition. Without an enforcement point in the graph,
// "bypassed everything" and "nothing to bypass" are one silence, and firing on
// it would light up every install that runs no plane at all.
func TestAnAgentNoEnforcementPointGovernsIsNotJudged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	sensorSaw(g, "agent://acme.example/planner", "203.0.113.7:443")

	if got := NewUnroutedEgress().Detect(g); len(got) != 0 {
		t.Errorf("want no findings where no plane governs anything, got %d: %+v", len(got), got)
	}
}

// The second precondition, and it is reported rather than dropped: a governed
// agent the sensor never saw is a coverage gap, not a clean bill of health.
func TestAGovernedAgentTheSensorNeverSawIsReportedAsUnjudged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 4, 0)
	governedBy(g, "agent://acme.example/auditor", 2, 0)
	// Some sensor evidence exists in this graph, just not for the auditor.
	sensorSaw(g, "agent://acme.example/planner", "203.0.113.7:443")

	a, ok := detect(NewUnroutedEgress(), g)["agent://acme.example/auditor"]
	if !ok {
		t.Fatal("a governed agent the sensor never saw must be reported, not silently dropped")
	}
	if a.Severity != model.SeverityInfo {
		t.Errorf("severity = %v, want info: this is missing evidence, not a finding about the agent", a.Severity)
	}
	for _, want := range []string{"not judged", "AGENT_PASSPORT_ID"} {
		if !strings.Contains(a.Summary, want) {
			t.Errorf("the coverage finding must say %q and why, got: %s", want, a.Summary)
		}
	}
}

// On an estate that does not run the optional eBPF layer at all, this detector
// says nothing whatever. Reporting the sensor's absence is the capture layer's
// own job (invariant 4), and a detector that nagged about a missing optional
// layer on every macOS estate is one an operator switches off.
func TestWithNoSensorEvidenceAtAllTheDetectorIsSilent(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 5, 2)

	if got := NewUnroutedEgress().Detect(g); len(got) != 0 {
		t.Errorf("want silence where the sensor contributed nothing, got %d: %+v", len(got), got)
	}
}

// The exclusion that keeps this detector alive on a real deployment, and it is
// counted rather than dropped. The plane's own address rules refuse these
// ranges, so a flow to one of them was never its to decide: it is the cluster's
// DNS, the other planes' gateways, and the enforcement point's own address.
func TestPrivateRangeDestinationsAreNotJudgedAndAreCounted(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 3, 0)
	sensorSaw(g, "agent://acme.example/planner",
		"10.96.0.10:53",         // cluster DNS
		"192.168.1.10:8080",     // something on the LAN
		"169.254.169.254:80",    // the metadata service
		"[fd00::1]:443",         // IPv6 unique-local
		"100.64.0.1:443",        // carrier-grade NAT
		"127.0.0.1:11434",       // the local model port the sensor deliberately keeps
		"wardryx.cluster.local", // named, not addressed
	)

	a, ok := detect(NewUnroutedEgress(), g)["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatal("a governed agent with only private-range egress must still be reported as unjudged")
	}
	if a.Severity != model.SeverityInfo {
		t.Errorf("severity = %v, want info: nothing here was the plane's to decide", a.Severity)
	}
	if !strings.Contains(a.Summary, "7 connection(s) to private, loopback or carrier-NAT ranges not judged") {
		t.Errorf("every excluded destination must be counted where a reader sees it, got: %s", a.Summary)
	}
}

// Model traffic belongs to a different plane and already has three detectors.
// Excluding it here is visible rather than silent: the count says so, and the
// same flow still produces a finding under its correct name elsewhere.
func TestModelAPIDestinationsAreLeftToTheShadowAIDetectorsAndCounted(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 3, 0)
	sensorSaw(g, "agent://acme.example/planner", "api.openai.com:443", "api.anthropic.com:443")

	a, ok := detect(NewUnroutedEgress(), g)["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatal("expected a coverage finding")
	}
	if a.Severity != model.SeverityInfo {
		t.Errorf("severity = %v, want info: model traffic is not this detector's finding", a.Severity)
	}
	if !strings.Contains(a.Summary, "2 connection(s) to model APIs left to the shadow-AI detectors") {
		t.Errorf("the exclusion must be counted, got: %s", a.Summary)
	}

	// And the claim in that sentence has to be true, or it is worse than no
	// sentence: shadow_ai must actually fire on the same identity.
	if _, ok := detect(NewShadowAI(), g)["claimed:agent://acme.example/planner"]; !ok {
		t.Error("unrouted_egress says the shadow-AI detectors own this traffic; shadow_ai did not fire on it")
	}
}

// A claim that names an agent no enforcement point governs is not this
// detector's subject at all. It is claimed_agent_unknown's, and firing here
// too would report one fact twice under two names.
func TestAClaimNamingAnAgentNoPlaneGovernsIsNotThisDetectorsFinding(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 3, 0)
	sensorSaw(g, "agent://acme.example/planner", "203.0.113.7:443")
	sensorSaw(g, "agent://acme.example/ghost", "198.51.100.9:443")

	got := detect(NewUnroutedEgress(), g)
	if _, ok := got["claimed:agent://acme.example/ghost"]; ok {
		t.Error("an ungoverned claim is claimed_agent_unknown's finding, not this one")
	}
	if _, ok := got["claimed:agent://acme.example/planner"]; !ok {
		t.Error("the governed agent must still be flagged in the same graph")
	}
}

// Determinism, which invariant 1 makes a hard rule: the same graph produces the
// same findings in the same order, and the destination named as the example is
// the same one every time rather than whichever the map yielded first.
func TestTheSameGraphProducesTheSameFindingsInTheSameOrder(t *testing.T) {
	withFixedNow(t)
	build := func() *graph.Store {
		g := graph.New(nil)
		governedBy(g, "agent://acme.example/planner", 2, 0)
		governedBy(g, "agent://acme.example/auditor", 2, 0)
		sensorSaw(g, "agent://acme.example/planner",
			"203.0.113.7:443", "198.51.100.9:443", "192.0.2.5:443")
		sensorSaw(g, "agent://acme.example/auditor", "203.0.113.8:443")
		return g
	}
	first := NewUnroutedEgress().Detect(build())
	if len(first) != 2 {
		t.Fatalf("want two findings, got %d", len(first))
	}
	for i := 0; i < 5; i++ {
		again := NewUnroutedEgress().Detect(build())
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d findings, first run produced %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].IdentityID != first[j].IdentityID || again[j].Summary != first[j].Summary {
				t.Fatalf("run %d differs at %d:\n first: %s\n again: %s",
					i, j, first[j].Summary, again[j].Summary)
			}
		}
	}
}

// One host reached a thousand times is one destination. Without this an agent
// polling a single endpoint would report a count that measures its cadence
// rather than its reach.
func TestRepeatedConnectionsToOneHostAreOneDestination(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	governedBy(g, "agent://acme.example/planner", 1, 0)
	dests := make([]string, 20)
	for i := range dests {
		dests[i] = "203.0.113.7:443"
	}
	sensorSaw(g, "agent://acme.example/planner", dests...)

	a := detect(NewUnroutedEgress(), g)["claimed:agent://acme.example/planner"]
	if !strings.Contains(a.Summary, "1 public destination(s)") {
		t.Errorf("want one destination, got: %s", a.Summary)
	}
}

// An IPv4 address wearing an IPv6 hat is the same private address, and a prefix
// test against the mapped form matches nothing at all.
func TestAnIPv4MappedPrivateAddressIsStillPrivate(t *testing.T) {
	if isPublicDestination("::ffff:10.0.0.1") {
		t.Error("::ffff:10.0.0.1 is 10.0.0.1 and must not be judged public")
	}
	if !isPublicDestination("::ffff:203.0.113.7") {
		t.Error("::ffff:203.0.113.7 is a public address and must be judged")
	}
}
