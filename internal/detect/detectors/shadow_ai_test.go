package detectors

import (
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
