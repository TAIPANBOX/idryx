package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// llmProvider is one recognised LLM API, in the two forms the estate needs it
// in, because they are not the same string and conflating them cost a false
// finding.
//
// id is the join key: agent-passport SPEC 4.7 registers the spelling, and a
// Passport's declared provider, a source scan's inventory and this observed
// side are compared against each other on it. 4.7 obliges a consumer to
// lowercase both sides and do nothing else, which is enough for every provider
// whose display name is one word and was not enough for Google: this map held
// "Google Gemini", and an agent that declared `google` and reached Google was
// reported as reaching an undeclared provider. A reader cannot tell that from
// real drift, and the fix it invites is editing a passport that was right.
//
// display is what a person reads in an alert summary. Ids are lowercase slugs
// by 4.7's grammar, and an alert saying "egress to external LLM API (openai)"
// reads like a leaked variable name.
type llmProvider struct {
	id      string
	display string
}

// llmHosts maps known LLM/AI-API hostnames to the provider they belong to. A
// match on egress means an identity is sending data to an external model - the
// signal for shadow AI (unsanctioned AI usage) and a data-exfiltration concern.
var llmHosts = map[string]llmProvider{
	"api.openai.com":                    {"openai", "OpenAI"},
	"api.anthropic.com":                 {"anthropic", "Anthropic"},
	"generativelanguage.googleapis.com": {"google", "Google Gemini"},
	"api.mistral.ai":                    {"mistral", "Mistral"},
	"api.cohere.ai":                     {"cohere", "Cohere"},
	"api.perplexity.ai":                 {"perplexity", "Perplexity"},
	"api.groq.com":                      {"groq", "Groq"},
	"api.together.xyz":                  {"together", "Together"},
	"openrouter.ai":                     {"openrouter", "OpenRouter"},
	"api.replicate.com":                 {"replicate", "Replicate"},
}

// ShadowAI flags identities whose egress reaches a known external LLM API. A
// service account or agent talking to an LLM is unsanctioned AI usage and a
// data-egress risk; a human doing so is informational.
type ShadowAI struct{}

func NewShadowAI() *ShadowAI { return &ShadowAI{} }

func (d *ShadowAI) Name() string { return "shadow_ai" }

func (d *ShadowAI) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		providers := map[string]bool{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress {
				continue
			}
			if provider, ok := matchLLM(e.Resource); ok {
				// The display name: this string is read by a person.
				providers[provider.display] = true
			}
		}
		if len(providers) == 0 {
			continue
		}
		// NHIs and agents sending data to an LLM are the real concern; a human
		// using AI is worth noting but low severity.
		sev := model.SeverityMedium
		if id.IsNHI() {
			sev = model.SeverityHigh
		}
		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    fmt.Sprintf("egress to external LLM API (%s)", strings.Join(sortedKeys(providers), ", ")),
		})
	}
	return alerts
}

// matchLLM returns the provider for a destination host, stripping any port and
// matching the registered LLM hosts (exact or subdomain).
func matchLLM(dest string) (llmProvider, bool) {
	host := dest
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if p, ok := llmHosts[host]; ok {
		return p, true
	}
	for h, p := range llmHosts {
		if strings.HasSuffix(host, "."+h) {
			return p, true
		}
	}
	return llmProvider{}, false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
