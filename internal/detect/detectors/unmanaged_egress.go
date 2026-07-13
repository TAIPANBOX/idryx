package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// UnmanagedEgress flags identities idryx only knows about through raw
// eBPF-observed network activity (internal/ebpfcapture): no IAM connector,
// no agent-event bus record, no Passport -- just a real outbound
// connection captured at the kernel level, labeled under a
// "proc:"-prefixed identity (see ebpfcapture.Identity). That is exactly
// the blind spot eBPF closes: an identity with ONLY this kind of evidence
// bypassed every higher-level connector idryx otherwise depends on to
// attribute activity to a governed agent or service account.
//
// Severity is medium by default (real activity, unattributed -- worth a
// look) and rises to high when the destination also matches a known LLM
// provider: ebpfcapture resolves and substitutes hostnames for known LLM
// IPs before emitting its flows (see capture_linux.go's knownLLMHosts), so
// this reuses matchLLM/llmHosts from shadow_ai.go rather than maintaining
// a second host list -- an unattributed process reaching an LLM API
// directly is the shadow-AI case eBPF exists to catch, the same
// governance gap tokenfuse's own radar targets.
type UnmanagedEgress struct{}

func NewUnmanagedEgress() *UnmanagedEgress { return &UnmanagedEgress{} }

func (d *UnmanagedEgress) Name() string { return "unmanaged_egress" }

func (d *UnmanagedEgress) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !strings.HasPrefix(id.ID, ebpfcapture.IdentityPrefix) {
			continue
		}
		var destinations []string
		llmProviders := map[string]bool{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress {
				continue
			}
			destinations = append(destinations, e.Resource)
			if provider, ok := matchLLM(e.Resource); ok {
				llmProviders[provider] = true
			}
		}
		if len(destinations) == 0 {
			continue
		}

		sev := model.SeverityMedium
		summary := fmt.Sprintf("network activity observed via eBPF, attributable only to process name (%d destination(s), e.g. %s) -- no IAM, agent-event, or Passport record for this identity",
			len(destinations), destinations[0])
		if len(llmProviders) > 0 {
			sev = model.SeverityHigh
			summary = fmt.Sprintf("unattributed process reached an external LLM API directly (%s), observed via eBPF with no governed connector recording it",
				strings.Join(sortedKeys(llmProviders), ", "))
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary:    summary,
		})
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].IdentityID < alerts[j].IdentityID })
	return alerts
}
