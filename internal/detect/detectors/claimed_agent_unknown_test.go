package detectors

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

const (
	knownAgent   = "agent://acme.example/support/tier1-bot"
	unknownAgent = "agent://acme.example/support/ghost"
)

func claimedAgentGraph() *graph.Store {
	g := graph.New(nil)

	// A claim naming an agent the graph knows from a Passport. This is the
	// case that must produce NOTHING: the two records agree.
	g.AddIdentity(model.Identity{ID: knownAgent, Type: model.IdentityAgent, Source: "passport", Owner: "team@acme.example"})
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+knownAgent, "api.openai.com:443"))

	// A claim naming an agent nothing else in the graph mentions, reaching an
	// LLM provider: the critical case.
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+unknownAgent, "api.anthropic.com:443"))

	// A claim naming an unknown agent, but reaching somewhere unremarkable:
	// still a finding, one band lower.
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+"agent://acme.example/etl/nightly", "203.0.113.9:443"))

	// An ordinary observed identity, no claim at all. unmanaged_egress's job,
	// never this detector's, even though it also reaches an LLM API.
	g.AddEvent(egress(ebpfcapture.Identity("python3", 8471), "api.openai.com:443"))

	return g
}

func TestClaimedAgentUnknown(t *testing.T) {
	withFixedNow(t)
	got := detect(NewClaimedAgentUnknown(), claimedAgentGraph())

	// The whole point of the detector: a claim the inventory confirms is not a
	// finding. If this fires, every correctly declared agent becomes an alert
	// and the detector gets switched off within a day.
	if _, ok := got[ebpfcapture.ClaimedPrefix+knownAgent]; ok {
		t.Error("a claim naming an agent the graph knows must not be flagged")
	}

	a, ok := got[ebpfcapture.ClaimedPrefix+unknownAgent]
	if !ok {
		t.Fatal("a claim naming an agent nothing else mentions must be flagged")
	}
	if a.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical when the unknown claim also reached an LLM API", a.Severity)
	}
	// The summary names the claimed identity, because an operator's first
	// action is to search their own deployment manifests for that string.
	if !strings.Contains(a.Summary, unknownAgent) {
		t.Errorf("summary does not name the claimed agent: %q", a.Summary)
	}

	b, ok := got[ebpfcapture.ClaimedPrefix+"agent://acme.example/etl/nightly"]
	if !ok {
		t.Fatal("an unknown claim reaching an ordinary host must still be flagged")
	}
	if b.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high without an LLM destination", b.Severity)
	}

	if _, ok := got[ebpfcapture.Identity("python3", 8471)]; ok {
		t.Error("an observed identity with no claim is unmanaged_egress's finding, not this one")
	}
}

// A claim is confirmed by any governed record of that agent, not only by a
// Passport. Narrowing it to Passports would flag every agent an operator
// tracks by some other means, which is a detector nobody keeps enabled.
func TestAClaimIsConfirmedByAnyRecordOfThatAgent(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	// Known from an agent-event source rather than a Passport document.
	g.AddIdentity(model.Identity{ID: knownAgent, Type: model.IdentityAgent, Source: "tokenfuse"})
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+knownAgent, "api.openai.com:443"))

	if got := detect(NewClaimedAgentUnknown(), g); len(got) != 0 {
		t.Errorf("a claim confirmed by a non-Passport source was still flagged: %v", got)
	}
}

// The claimed URI is compared exactly. A prefix or suffix relationship between
// two agent paths is not a match: agent://acme.example/support and
// agent://acme.example/support/bot are different agents, and treating one as
// confirming the other would let an unknown sub-agent hide behind a declared
// parent.
func TestASimilarButDifferentAgentDoesNotConfirmAClaim(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{ID: "agent://acme.example/support", Type: model.IdentityAgent, Source: "passport"})
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+"agent://acme.example/support/bot", "203.0.113.9:443"))

	if got := detect(NewClaimedAgentUnknown(), g); len(got) != 1 {
		t.Errorf("a sub-path claim was treated as confirmed by its parent: %v", got)
	}
}
