package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// ClaimedAgentUnknown flags a process that named itself with an agent:// URI
// (agent-passport SPEC 3.3, carried in AGENT_PASSPORT_ID and captured by
// internal/ebpfcapture) which appears nowhere else in the graph: no Passport,
// no IAM record, no agent-event, nothing.
//
// **Why a claim with no backing is worth its own detector rather than a note
// on unmanaged_egress.** The two describe opposite situations and a reader
// needs to tell them apart. unmanaged_egress is silence: something ran and
// said nothing about itself, so idryx knows only a process name. This is an
// assertion: something ran and named an identity that the organisation's own
// inventory has never heard of. Silence is usually an unmanaged workload;
// an assertion that resolves to nothing is either a real agent nobody
// declared, or a name somebody invented, and both are answerable questions
// where silence is only a starting point.
//
// **What a finding here does NOT mean.** It is not evidence of impersonation.
// The likeliest cause by far is an inventory gap or a typo in a deployment
// manifest, and the summary says so rather than accusing: a claim naming an
// agent that DOES exist is not flagged at all, which is exactly the case
// impersonation would produce. SPEC 3.3 is explicit that the variable is
// self-declared and proves nothing, so this detector reports a discrepancy
// between two of the operator's own records and never a verdict about intent.
//
// Severity is high by default, above unmanaged_egress's medium, because an
// unrecognised assertion is a stronger signal than an absent one, and rises to
// critical when the same identity was also seen reaching a known LLM provider:
// an undeclared agent talking to a model API is the shadow-AI case with a name
// attached.
type ClaimedAgentUnknown struct{}

func NewClaimedAgentUnknown() *ClaimedAgentUnknown { return &ClaimedAgentUnknown{} }

func (d *ClaimedAgentUnknown) Name() string { return "claimed_agent_unknown" }

func (d *ClaimedAgentUnknown) Detect(g graph.Reader) []model.Alert {
	identities := g.Identities()

	// Every identity the graph knows by its own name, from any governed
	// source: a Passport, an IAM inventory, an agent-event, an agents file.
	// The claim is checked against all of them rather than against Passports
	// alone, because the question is "has this organisation ever heard of this
	// agent", not "was a Passport document ingested in this run". Narrowing it
	// to Passports would report every agent an operator tracks by some other
	// means, which is a detector nobody keeps switched on.
	known := make(map[string]bool, len(identities))
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) {
			known[id.ID] = true
		}
	}

	var alerts []model.Alert
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		claimed := strings.TrimPrefix(id.ID, ebpfcapture.ClaimedPrefix)
		if known[claimed] {
			continue // the claim resolves; nothing to say
		}

		// Only the LLM providers, deliberately: unlike unmanaged_egress, this
		// detector's summary names the claimed agent rather than where it
		// went, because that string is what an operator greps their own
		// deployment manifests for. Collecting destinations here was copied
		// from that detector and used by nothing, which staticcheck caught.
		llmProviders := map[string]bool{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress {
				continue
			}
			if provider, ok := matchLLM(e.Resource); ok {
				llmProviders[provider] = true
			}
		}

		sev := model.SeverityHigh
		summary := fmt.Sprintf("a process declared itself %s (AGENT_PASSPORT_ID), and no Passport, IAM record or agent-event in this graph names that agent: either it is undeclared, or the value is wrong",
			claimed)
		if len(llmProviders) > 0 {
			sev = model.SeverityCritical
			summary = fmt.Sprintf("a process declared itself %s (AGENT_PASSPORT_ID) and reached an external LLM API (%s); no Passport, IAM record or agent-event in this graph names that agent",
				claimed, strings.Join(sortedKeys(llmProviders), ", "))
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
