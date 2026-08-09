package detectors

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

const declaringAgent = "agent://acme.example/support/declared-bot"

// withPassport puts an agent in the graph the way internal/ingest/passport
// does: an identity under its own agent:// URI, carrying its declaration.
func withPassport(g *graph.Store, id string, providers ...string) {
	var models []model.DeclaredModel
	for _, p := range providers {
		models = append(models, model.DeclaredModel{Provider: p})
	}
	g.AddIdentity(model.Identity{
		ID: id, Type: model.IdentityAgent, Source: "passport",
		Owner: "team@acme.example", DeclaredModels: models,
	})
}

func TestAClaimedProcessReachingAnUndeclaredProviderIsFlagged(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	withPassport(g, declaringAgent, "anthropic")
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+declaringAgent, "api.openai.com:443"))

	got := detect(NewClaimedAgentDrift(), g)
	a, ok := got[ebpfcapture.ClaimedPrefix+declaringAgent]
	if !ok {
		t.Fatal("a claimed process reaching a provider its Passport does not declare must be flagged")
	}
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", a.Severity)
	}
	// Both readings must stay open in the wording: SPEC 3.3 says the claim is
	// self-declared, so asserting the agent did this would be a claim idryx
	// cannot support.
	if !strings.Contains(a.Summary, "claiming to be") {
		t.Errorf("summary asserts the claim rather than reporting it: %q", a.Summary)
	}
	if !strings.Contains(a.Summary, "or something else is using its name") {
		t.Errorf("summary closes off the impersonation reading: %q", a.Summary)
	}
	// It must name both sides, or an operator cannot act on it. Compared
	// case-insensitively: matchLLM returns a display label ("OpenAI") while a
	// Passport carries whatever its author typed, and this test is about both
	// sides being NAMED, not about how either is capitalised.
	low := strings.ToLower(a.Summary)
	if !strings.Contains(low, "openai") || !strings.Contains(low, "anthropic") {
		t.Errorf("summary does not name observed and declared: %q", a.Summary)
	}
}

// The declared provider is the whole point of the comparison: reaching exactly
// what the Passport allows is the normal case and must be silent.
func TestAClaimedProcessStayingWithinItsDeclarationIsSilent(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	withPassport(g, declaringAgent, "openai")
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+declaringAgent, "api.openai.com:443"))

	if got := detect(NewClaimedAgentDrift(), g); len(got) != 0 {
		t.Errorf("an agent reaching exactly what it declared was flagged: %v", got)
	}
}

// A claim naming an agent with no Passport at all belongs to
// claimed_agent_unknown. Two detectors reporting one fact would double every
// count an operator sorts by.
func TestAClaimWithNoPassportIsTheOtherDetectorsFinding(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+"agent://acme.example/ghost", "api.openai.com:443"))

	if got := detect(NewClaimedAgentDrift(), g); len(got) != 0 {
		t.Errorf("an unknown claim was flagged here as well as by claimed_agent_unknown: %v", got)
	}
}

// An agent whose Passport declares nothing has not been contradicted: absent is
// not "no model use" (SPEC 4.5), and treating it as one would flag every agent
// whose owner simply has not filled the field in.
func TestAnAgentThatDeclaredNothingCannotDrift(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	withPassport(g, declaringAgent) // no models
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+declaringAgent, "api.openai.com:443"))

	if got := detect(NewClaimedAgentDrift(), g); len(got) != 0 {
		t.Errorf("an agent with no declaration was reported as drifting: %v", got)
	}
}

// An exact endpoint in the Passport covers that host even when the provider
// label does not match, which is how SPEC 4.5's endpoint field is meant to work.
func TestAnExactEndpointInThePassportCoversTheHost(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: declaringAgent, Type: model.IdentityAgent, Source: "passport",
		DeclaredModels: []model.DeclaredModel{{Provider: "self-hosted", Endpoint: "api.openai.com"}},
	})
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+declaringAgent, "api.openai.com:443"))

	if got := detect(NewClaimedAgentDrift(), g); len(got) != 0 {
		t.Errorf("a host the Passport names by endpoint was reported as undeclared: %v", got)
	}
}

// Non-LLM traffic is not this detector's subject at all: an agent declares
// model use, not every host it may contact.
func TestOrdinaryTrafficIsNotDrift(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	withPassport(g, declaringAgent, "anthropic")
	g.AddEvent(egress(ebpfcapture.ClaimedPrefix+declaringAgent, "203.0.113.9:443"))

	if got := detect(NewClaimedAgentDrift(), g); len(got) != 0 {
		t.Errorf("ordinary egress was reported as model drift: %v", got)
	}
}
