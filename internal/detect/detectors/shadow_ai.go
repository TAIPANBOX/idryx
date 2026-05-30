package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// llmHosts maps known LLM/AI-API hostnames to the provider they belong to. A
// match on egress means an identity is sending data to an external model — the
// signal for shadow AI (unsanctioned AI usage) and a data-exfiltration concern.
var llmHosts = map[string]string{
	"api.openai.com":                    "OpenAI",
	"api.anthropic.com":                 "Anthropic",
	"generativelanguage.googleapis.com": "Google Gemini",
	"api.mistral.ai":                    "Mistral",
	"api.cohere.ai":                     "Cohere",
	"api.perplexity.ai":                 "Perplexity",
	"api.groq.com":                      "Groq",
	"api.together.xyz":                  "Together",
	"openrouter.ai":                     "OpenRouter",
	"api.replicate.com":                 "Replicate",
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
				providers[provider] = true
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
func matchLLM(dest string) (string, bool) {
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
	return "", false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
