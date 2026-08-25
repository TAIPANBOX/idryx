package detectors

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// undeclaredLLMGraph builds one fixture covering the declared-vs-observed
// discrepancy trigger, the two suppression paths (provider match, exact
// endpoint-host match), the "no declaration at all" carve-out, the
// privilege escalation, the one-alert-per-identity dedup across multiple
// undeclared providers, and the agent-only restriction.
func undeclaredLLMGraph() *graph.Store {
	g := graph.New(nil)

	// Declared anthropic only; observed reaching OpenAI -> undeclared, high.
	g.AddIdentity(model.Identity{
		ID: "agent:drift-to-openai", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("agent:drift-to-openai", "api.openai.com"))

	// Declared anthropic; observed reaching Anthropic only -> matches the
	// declaration by provider, no alert.
	g.AddIdentity(model.Identity{
		ID: "agent:matches-declared-provider", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("agent:matches-declared-provider", "api.anthropic.com"))

	// No declared models at all; observed reaching OpenAI -> out of scope
	// for this detector (shadow_ai's job), even though the egress itself
	// looks identical to the drift-to-openai case above.
	g.AddIdentity(model.Identity{ID: "agent:no-declaration", Type: model.IdentityAgent})
	g.AddEvent(egress("agent:no-declaration", "api.openai.com"))

	// Declared a specific endpoint (with provider matching too); observed
	// reaching exactly that endpoint, on a different port -> matches by
	// exact host once the port is stripped, no alert.
	g.AddIdentity(model.Identity{
		ID: "agent:matches-endpoint", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic", Endpoint: "api.anthropic.com"}},
	})
	g.AddEvent(egress("agent:matches-endpoint", "api.anthropic.com:443"))

	// Declared endpoint matches the observed host exactly, but the declared
	// *provider* name would not have matched matchLLM's own canonical name
	// for that host -- isolates the endpoint-exact-match suppression path
	// from the provider-match path (both must independently suppress).
	g.AddIdentity(model.Identity{
		ID: "agent:matches-endpoint-only", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "acme-custom-proxy", Endpoint: "api.anthropic.com"}},
	})
	g.AddEvent(egress("agent:matches-endpoint-only", "api.anthropic.com"))

	// Declared anthropic, egress to a non-LLM host -> matchLLM never
	// matches it, so it is not a discrepancy at all.
	g.AddIdentity(model.Identity{
		ID: "agent:benign-egress", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("agent:benign-egress", "github.com"))

	// Declared anthropic, Privileged; observed reaching OpenAI -> undeclared
	// AND privileged, escalates to critical.
	g.AddIdentity(model.Identity{
		ID: "agent:privileged-drift", Type: model.IdentityAgent, Privileged: true,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("agent:privileged-drift", "api.openai.com"))

	// Declared anthropic; observed reaching TWO different undeclared
	// providers -> exactly one alert (not one per provider/event),
	// summarizing both.
	g.AddIdentity(model.Identity{
		ID: "agent:multi-undeclared", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("agent:multi-undeclared", "api.openai.com"))
	g.AddEvent(egress("agent:multi-undeclared", "api.mistral.ai"))

	// Declared models present, but on a non-agent identity type -> must
	// never be flagged; this detector is agent-only regardless of
	// DeclaredModels being set.
	g.AddIdentity(model.Identity{
		ID: "role:not-an-agent", Type: model.IdentityServiceAccount,
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
	})
	g.AddEvent(egress("role:not-an-agent", "api.openai.com"))

	return g
}

func TestUndeclaredLLM(t *testing.T) {
	withFixedNow(t)
	got := detect(NewUndeclaredLLM(), undeclaredLLMGraph())

	cases := []struct {
		id   string
		want model.Severity
	}{
		{"agent:drift-to-openai", model.SeverityHigh},
		{"agent:privileged-drift", model.SeverityCritical},
		{"agent:multi-undeclared", model.SeverityHigh},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected an undeclared_llm finding, got none", c.id)
			continue
		}
		if a.Severity != c.want {
			t.Errorf("%s: severity = %v, want %v (summary: %s)", c.id, a.Severity, c.want, a.Summary)
		}
	}

	// The drift case names the declared provider and the undeclared one.
	if a, ok := got["agent:drift-to-openai"]; ok {
		if !strings.Contains(a.Summary, "anthropic") {
			t.Errorf("summary should name the declared provider: %q", a.Summary)
		}
		if !strings.Contains(a.Summary, "OpenAI") || !strings.Contains(a.Summary, "api.openai.com") {
			t.Errorf("summary should name the undeclared provider and host: %q", a.Summary)
		}
	}

	// The multi-provider case must still be exactly one alert, naming both
	// undeclared providers in that single summary.
	if a, ok := got["agent:multi-undeclared"]; !ok {
		t.Error("agent:multi-undeclared: expected one finding")
	} else if !strings.Contains(a.Summary, "OpenAI") || !strings.Contains(a.Summary, "Mistral") {
		t.Errorf("summary should name both undeclared providers: %q", a.Summary)
	}
}

func TestUndeclaredLLMNoFindingCases(t *testing.T) {
	withFixedNow(t)
	got := detect(NewUndeclaredLLM(), undeclaredLLMGraph())

	for _, id := range []string{
		"agent:matches-declared-provider",
		"agent:no-declaration",
		"agent:matches-endpoint",
		"agent:matches-endpoint-only",
		"agent:benign-egress",
		"role:not-an-agent",
	} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no undeclared_llm finding, got %+v", id, a)
		}
	}
}

// TestUndeclaredLLMExactlyOneAlertPerIdentity guards the dedupe requirement
// directly: an identity with several undeclared egress events/providers
// must never produce more than one alert.
func TestUndeclaredLLMExactlyOneAlertPerIdentity(t *testing.T) {
	withFixedNow(t)
	count := 0
	for _, a := range NewUndeclaredLLM().Detect(undeclaredLLMGraph()) {
		if a.IdentityID == "agent:multi-undeclared" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("agent:multi-undeclared: got %d alerts, want exactly 1", count)
	}
}

// TestUndeclaredLLMDeterministic mirrors mcp_drift's determinism check: same
// graph, two Detect calls, identical output (guards against the map-based
// grouping in Detect making output order- or content-unstable).
func TestUndeclaredLLMDeterministic(t *testing.T) {
	withFixedNow(t)
	g := undeclaredLLMGraph()
	first := NewUndeclaredLLM().Detect(g)
	second := NewUndeclaredLLM().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

// TestUndeclaredLLMGoogleDeclarationIsHonoured is the whole reason the
// observed side carries a registered id rather than a display name.
//
// agent-passport SPEC 4.7 registers `google` as the id naming Google's
// generative language API. This detector lowercases both sides before
// comparing, which 4.7 requires and which is enough for every other provider
// here: "OpenAI" lowercases onto `openai`, "Groq" onto `groq`. It is not
// enough for one, because the observed side used to call it "Google Gemini",
// and "google gemini" is not "google".
//
// The consequence was not cosmetic. An agent that declares Google and reaches
// Google was reported as reaching an undeclared provider, which is the one
// thing an inventory must never do: the reader cannot tell it from real drift,
// and the fix they would reach for is editing a passport that was already
// right.
func TestUndeclaredLLMGoogleDeclarationIsHonoured(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "agent:declares-google", Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{{Provider: "google"}},
	})
	g.AddEvent(egress("agent:declares-google", "generativelanguage.googleapis.com"))

	if a, ok := detect(NewUndeclaredLLM(), g)["agent:declares-google"]; ok {
		t.Errorf("an agent declaring google and reaching google was reported as drift: %q", a.Summary)
	}
}

// TestUndeclaredLLMAzureAndVertexAreTheirOwnProviders exercises SPEC 4.7's
// rule on the two ids the registry just gained: an id names the API surface the
// bytes leave for, not the model family behind it. The same model reached
// through Azure is a request to Microsoft, and through Vertex a request to
// Google Cloud rather than to the generative language API, so `azure-openai` is
// not `openai` and `vertex` is not `google`.
//
// Every case is asserted in both directions, because only the pair says
// anything. A suppression that is too wide reports nothing at all, and an
// estate with no findings looks exactly like a clean one.
func TestUndeclaredLLMAzureAndVertexAreTheirOwnProviders(t *testing.T) {
	withFixedNow(t)

	cases := []struct {
		name      string
		declared  string
		reached   string
		wantDrift bool
		names     string // what the summary must name when it does fire
	}{
		{"azure declared, azure reached", "azure-openai", "contoso.openai.azure.com", false, ""},
		{"azure declared, foundry reached", "azure-openai", "contoso.services.ai.azure.com", false, ""},
		{"openai declared, azure reached", "openai", "contoso.openai.azure.com", true, "Azure OpenAI"},
		{"vertex declared, regional vertex reached", "vertex", "us-central1-aiplatform.googleapis.com", false, ""},
		{"google declared, vertex reached", "google", "us-central1-aiplatform.googleapis.com", true, "Google Vertex AI"},
		{"vertex declared, gemini reached", "vertex", "generativelanguage.googleapis.com", true, "Google Gemini"},
		{"anthropic declared, azure reached", "anthropic", "contoso.openai.azure.com", true, "Azure OpenAI"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := graph.New(nil)
			g.AddIdentity(model.Identity{
				ID: "agent:x", Type: model.IdentityAgent,
				DeclaredModels: []model.DeclaredModel{{Provider: c.declared}},
			})
			g.AddEvent(egress("agent:x", c.reached))

			a, ok := detect(NewUndeclaredLLM(), g)["agent:x"]
			if ok != c.wantDrift {
				t.Fatalf("declared %q, reached %q: drift reported = %v, want %v (summary %q)",
					c.declared, c.reached, ok, c.wantDrift, a.Summary)
			}
			if c.wantDrift && !strings.Contains(a.Summary, c.names) {
				t.Errorf("summary %q does not name %q", a.Summary, c.names)
			}
		})
	}
}

// TestObservedProviderIdsAreTheRegisteredOnes pins the observed-side
// vocabulary the same way the declared side is pinned, and for the same
// reason: these ids are a join key across three repositories, and a
// misspelling here reports drift that does not exist.
func TestObservedProviderIdsAreTheRegisteredOnes(t *testing.T) {
	// agent-passport SPEC 4.7, as of 2026-08-25. `azure-openai` and `vertex`
	// joined it that day (agent-passport PR #39) and are ids of their own
	// rather than spellings of `openai` and `google`, because 4.7's id names
	// the API surface the bytes leave for: Azure is Microsoft, and Vertex is
	// Google Cloud rather than the generative language API.
	registered := map[string]bool{
		"anthropic": true, "openai": true, "google": true, "bedrock": true,
		"mistral": true, "cohere": true, "groq": true, "together": true,
		"perplexity": true, "replicate": true, "openrouter": true,
		"huggingface": true, "ollama": true,
		"azure-openai": true, "vertex": true,
	}
	if len(llmHosts) == 0 {
		t.Fatal("no LLM hosts at all: this test measured nothing")
	}
	for host, p := range llmHosts {
		if !registered[p.id] {
			t.Errorf("%s: provider id %q is not registered in agent-passport SPEC 4.7", host, p.id)
		}
		if p.display == "" {
			t.Errorf("%s: provider id %q has no display name, so an alert would read as a slug", host, p.id)
		}
	}
}
