package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// UndeclaredLLM flags AI agents whose Passport declares which LLM
// providers/models they are meant to use (agent-passport SPEC §4.5) but
// whose observed network egress reaches a different, undeclared LLM
// provider. This is the declared-vs-observed correlation leg of idryx's
// three-source AI inventory: declared (the Passport's Models field, mapped
// into model.Identity.DeclaredModels by internal/ingest/passport), observed
// (egress events matched against known LLM hosts via matchLLM, shared with
// shadow_ai), and coded (a future qryx code-scan integration, not built
// here).
//
// An agent that never declared any models has nothing to drift from, and
// any LLM egress it makes is already shadow_ai's concern (or, for
// eBPF-only identities with no governed record at all,
// unmanaged_egress's) -- this detector deliberately skips them rather than
// duplicating that coverage. Only an agent that DID declare at least one
// model, and is then observed reaching an LLM host outside that
// declaration, is real inventory drift: a governed agent whose actual AI
// usage no longer matches what it told the org it uses.
type UndeclaredLLM struct{}

func NewUndeclaredLLM() *UndeclaredLLM { return &UndeclaredLLM{} }

func (d *UndeclaredLLM) Name() string { return "undeclared_llm" }

func (d *UndeclaredLLM) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() || len(id.DeclaredModels) == 0 {
			continue
		}

		// The declared side: providers (lowercased, so comparison is
		// case-insensitive regardless of how the Passport capitalized
		// them) and exact endpoint hosts (lowercased, port-stripped, same
		// normalization matchLLM applies to observed destinations).
		declaredProviders := map[string]bool{}
		declaredHosts := map[string]bool{}
		for _, m := range id.DeclaredModels {
			if m.Provider != "" {
				declaredProviders[strings.ToLower(m.Provider)] = true
			}
			if m.Endpoint != "" {
				declaredHosts[normalizeHost(m.Endpoint)] = true
			}
		}

		// The observed side: walk egress, keep only destinations matchLLM
		// recognizes as an LLM API, and drop any that the declaration
		// already covers by provider or by exact endpoint host. What is
		// left is grouped provider -> hosts seen, so one agent reaching
		// the same undeclared provider on several hosts (or the same host
		// via several events) still collapses to one line, not a repeat
		// per event.
		undeclared := map[string]map[string]bool{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress {
				continue
			}
			provider, ok := matchLLM(e.Resource)
			if !ok {
				continue
			}
			if declaredProviders[strings.ToLower(provider)] {
				continue // declared by provider: not a discrepancy
			}
			host := normalizeHost(e.Resource)
			if declaredHosts[host] {
				continue // declared by exact endpoint: not a discrepancy
			}
			if undeclared[provider] == nil {
				undeclared[provider] = map[string]bool{}
			}
			undeclared[provider][host] = true
		}
		if len(undeclared) == 0 {
			continue
		}

		// A governed agent that declared its models but reached an
		// undeclared LLM provider is real inventory drift, a possible
		// shadow-AI use riding on an otherwise-trusted identity. Standing
		// privilege/admin access raises it further -- the same
		// privileged/admin escalation mcp_drift and tainted_agent use.
		sev := model.SeverityHigh
		if id.Privileged || id.HasAdmin() {
			sev = model.SeverityCritical
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    undeclaredLLMSummary(declaredProviders, undeclared),
		})
	}
	return alerts
}

// normalizeHost strips any port and lowercases dest, so a declared endpoint
// and an observed egress destination compare equal regardless of port or
// case. This mirrors matchLLM's own normalization (shadow_ai.go) so both
// sides of the comparison stay consistent; kept as its own small copy here
// rather than exported from shadow_ai.go, which this detector leaves
// unmodified.
func normalizeHost(dest string) string {
	host := dest
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// undeclaredLLMSummary renders one human-readable line naming what the
// Passport declared and which undeclared LLM provider(s)/host(s) were
// actually observed. Both the declared-provider list and, within each
// undeclared provider, its host list are sorted for a deterministic result
// independent of map iteration order.
func undeclaredLLMSummary(declaredProviders map[string]bool, undeclared map[string]map[string]bool) string {
	providers := make([]string, 0, len(undeclared))
	for p := range undeclared {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	parts := make([]string, 0, len(providers))
	for _, p := range providers {
		parts = append(parts, fmt.Sprintf("%s (%s)", p, strings.Join(sortedKeys(undeclared[p]), ", ")))
	}

	return fmt.Sprintf("declared models [%s] but observed egress to undeclared LLM provider(s) %s",
		strings.Join(sortedKeys(declaredProviders), ", "), strings.Join(parts, ", "))
}
