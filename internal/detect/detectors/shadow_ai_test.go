package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func egress(id, dest string) model.Event {
	return model.Event{
		IdentityID: id, Type: model.EventEgress, Outcome: "SUCCESS",
		Resource: dest, Time: time.Now(),
	}
}

func shadowGraph() *graph.Store {
	g := graph.New(nil)
	// NHI talking to OpenAI -> high
	g.AddIdentity(model.Identity{ID: "arn:role/etl", Type: model.IdentityServiceAccount, Source: "aws_iam"})
	g.AddEvent(egress("arn:role/etl", "api.openai.com:443"))
	// human talking to Anthropic -> medium
	g.AddEvent(egress("alice@x.com", "api.anthropic.com"))
	// identity with only benign egress -> nothing
	g.AddEvent(egress("bob@x.com", "github.com"))
	return g
}

func TestShadowAI(t *testing.T) {
	withFixedNow(t)
	got := detect(NewShadowAI(), shadowGraph())

	if a, ok := got["arn:role/etl"]; !ok {
		t.Error("etl NHI egress to OpenAI should be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("NHI shadow AI severity = %v, want high", a.Severity)
	}
	if a, ok := got["alice@x.com"]; !ok {
		t.Error("human egress to Anthropic should be flagged")
	} else if a.Severity != model.SeverityMedium {
		t.Errorf("human shadow AI severity = %v, want medium", a.Severity)
	}
	if _, ok := got["bob@x.com"]; ok {
		t.Error("benign egress must not be flagged")
	}
}

func TestMatchLLM(t *testing.T) {
	cases := map[string]bool{
		"api.openai.com":       true,
		"api.openai.com:443":   true,
		"eu.api.anthropic.com": true, // subdomain
		"API.OPENAI.COM":       true, // case-insensitive
		"github.com":           false,
		"notopenai.com":        false,
	}
	for host, want := range cases {
		if _, ok := matchLLM(host); ok != want {
			t.Errorf("matchLLM(%q) = %v, want %v", host, ok, want)
		}
	}
}

// TestMatchLLMAzureAndVertexEndpointForms pins the shapes a real deployment
// actually connects to, which are not the shapes the registry keys are written
// in.
//
// Azure gives every resource its own subdomain, so nothing ever opens a
// connection to `openai.azure.com` itself: the traffic goes to
// `<resource>.openai.azure.com`, and the existing "." + host pass already
// carries that. It is asserted here rather than assumed, because the whole
// entry is worthless if it does not.
//
// Vertex is the one that does not fit that pass. A regional endpoint glues the
// region onto the FRONT of the host with a hyphen,
// `us-central1-aiplatform.googleapis.com`, which is not a subdomain of
// `aiplatform.googleapis.com` and never matches a dot rule. Almost every real
// call goes to a regional endpoint, so a registry entry without this would be
// present and still blind.
func TestMatchLLMAzureAndVertexEndpointForms(t *testing.T) {
	cases := map[string]string{
		"openai.azure.com":                           "azure-openai",
		"my-resource.openai.azure.com":               "azure-openai",
		"contoso.cognitiveservices.azure.com":        "azure-openai",
		"contoso.services.ai.azure.com":              "azure-openai",
		"aiplatform.googleapis.com":                  "vertex",
		"us-central1-aiplatform.googleapis.com":      "vertex",
		"europe-west4-aiplatform.googleapis.com:443": "vertex",
		"US-CENTRAL1-AIPLATFORM.GOOGLEAPIS.COM":      "vertex",
	}
	for host, want := range cases {
		p, ok := matchLLM(host)
		if !ok {
			t.Errorf("matchLLM(%q): not recognised as a model API at all", host)
			continue
		}
		if p.id != want {
			t.Errorf("matchLLM(%q).id = %q, want %q", host, p.id, want)
		}
	}
}

// TestRegionalPrefixIsOptInPerHost is the test for what could go wrong with the
// rule above, and the reason that rule belongs to one registered host instead
// of to the matcher.
//
// A dot is a boundary somebody else already owns: anything ending in
// `.openrouter.ai` was handed out by OpenRouter. A hyphen is not. The same rule
// applied to every entry would read `fake-openrouter.ai` as OpenRouter, and
// that is a name anyone can register for the price of a domain. Naming the
// wrong company in an alert is the visible half. The silent half is worse:
// undeclared_llm SUPPRESSES a finding when the observed provider is one the
// Passport declared, so an agent that declares openrouter and is exfiltrating
// to a lookalike domain would have that egress filed as expected traffic.
//
// `-aiplatform.googleapis.com` carries none of that, which is why it is the one
// entry that opts in: whatever sits before the hyphen is a label under
// googleapis.com, and Google allocates those, so no third party can occupy one.
func TestRegionalPrefixIsOptInPerHost(t *testing.T) {
	for _, host := range []string{
		// A different registrable domain, and the case this test exists for.
		"fake-openrouter.ai",
		// Under googleapis.com, but no hyphen and no dot: a rule written with
		// strings.Contains or a TrimPrefix would take it.
		"notaiplatform.googleapis.com",
		// The registered host appears in full, as somebody else's subdomain.
		"aiplatform.googleapis.com.evil.net",
		"openai.azure.com.evil.net",
	} {
		if p, ok := matchLLM(host); ok {
			t.Errorf("matchLLM(%q) = %q, want no match: that host is not the provider it resembles", host, p.id)
		}
	}
}

// TestNoRegisteredHostShadowsAnother keeps matchLLM's answer deterministic
// (invariant 1) as the registry grows. The suffix pass walks a Go map, and Go
// randomises map order per run, so a destination that two registered entries
// both match would resolve to whichever came up first: same graph in, different
// provider out, on different runs. Nothing in matchLLM prevents that pair from
// being registered; this does.
//
// It became worth writing when the registry gained two hosts under one parent,
// `cognitiveservices.azure.com` and `services.ai.azure.com`, which is the shape
// that eventually produces a pair where one is a suffix of the other: the
// obvious way to add a regional Azure endpoint is to paste in the host somebody
// read off a portal, and `westeurope.openai.azure.com` is already covered by
// the entry above it.
func TestNoRegisteredHostShadowsAnother(t *testing.T) {
	if len(llmHosts) == 0 {
		t.Fatal("no registered hosts at all: this test measured nothing")
	}
	for a := range llmHosts {
		for b := range llmHosts {
			if a == b {
				continue
			}
			// The two rules matchLLM applies, mirrored exactly.
			if strings.HasSuffix(a, "."+b) || (regionalPrefixHosts[b] && strings.HasSuffix(a, "-"+b)) {
				t.Errorf("registered host %q is also matched by the entry for %q, so which provider matchLLM returns for it depends on map iteration order", a, b)
			}
		}
	}
}

// TestShadowAIFlagsAzureAndVertex is the detector-level half of the matcher
// tests: a service account reaching Azure OpenAI or a regional Vertex endpoint
// is the same shadow-AI finding as one reaching api.openai.com, and the summary
// names the surface the bytes left for rather than the model family behind it.
func TestShadowAIFlagsAzureAndVertex(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{ID: "arn:role/azure-etl", Type: model.IdentityServiceAccount, Source: "aws_iam"})
	g.AddEvent(egress("arn:role/azure-etl", "contoso.openai.azure.com:443"))
	g.AddIdentity(model.Identity{ID: "arn:role/vertex-etl", Type: model.IdentityServiceAccount, Source: "gcp_iam"})
	g.AddEvent(egress("arn:role/vertex-etl", "us-central1-aiplatform.googleapis.com:443"))

	got := detect(NewShadowAI(), g)
	for id, want := range map[string]string{
		"arn:role/azure-etl":  "Azure OpenAI",
		"arn:role/vertex-etl": "Google Vertex AI",
	} {
		a, ok := got[id]
		if !ok {
			t.Errorf("%s: expected a shadow_ai finding, got none", id)
			continue
		}
		if a.Severity != model.SeverityHigh {
			t.Errorf("%s: severity = %v, want high (an NHI reaching a model API)", id, a.Severity)
		}
		if !strings.Contains(a.Summary, want) {
			t.Errorf("%s: summary %q does not name %q", id, a.Summary, want)
		}
	}
}
