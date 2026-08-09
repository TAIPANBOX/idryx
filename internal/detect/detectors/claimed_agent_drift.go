package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// ClaimedAgentDrift flags a process that named itself an agent whose Passport
// exists and declares different model use than the process was observed making.
//
// **This is the other half of claimed_agent_unknown, and the pair covers the
// two answers a claim can have.** A claim naming an agent nobody issued is that
// detector's finding. A claim naming an agent that DOES exist produced nothing
// at all until this one, which left the most useful comparison in the stack
// unmade: the Passport says which providers the agent is meant to use (SPEC
// 4.5), the sensor sees which it actually reached, and nobody put the two
// side by side.
//
// **Why not extend undeclared_llm instead.** That detector answers a different
// question about a different subject: a governed agent identity, established by
// a connector, whose own events drift from its own declaration. Its selector is
// `IsAgent() && len(DeclaredModels) > 0`, and a claimed identity has neither:
// it is an egress-only identity created from a captured connection, carrying no
// type and no declaration. Widening that selector would make one detector mean
// two things, and the weaker of the two would inherit the stronger one's
// wording.
//
// **The wording never asserts the claim is true, and that is the constraint
// this detector is written around.** agent-passport SPEC 3.3 says an identity
// learned from AGENT_PASSPORT_ID is self-declared: the process wrote its own
// environment. So the finding says "a process claiming to be X reached Y, and
// X's Passport declares Z". Both readings stay open and both are worth an
// operator's time: either the agent is drifting from its own declaration, or
// something is using its name.
type ClaimedAgentDrift struct{}

func NewClaimedAgentDrift() *ClaimedAgentDrift { return &ClaimedAgentDrift{} }

func (d *ClaimedAgentDrift) Name() string { return "claimed_agent_drift" }

func (d *ClaimedAgentDrift) Detect(g graph.Reader) []model.Alert {
	identities := g.Identities()

	// The declarations, keyed by the agent:// URI they belong to. Only
	// identities that actually carry one: an agent in the graph with no
	// `models` block has declared nothing, and nothing is not a contradiction.
	declared := map[string][]model.DeclaredModel{}
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) && len(id.DeclaredModels) > 0 {
			declared[id.ID] = id.DeclaredModels
		}
	}
	if len(declared) == 0 {
		return nil
	}

	var alerts []model.Alert
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		claimed := strings.TrimPrefix(id.ID, ebpfcapture.ClaimedPrefix)
		models, ok := declared[claimed]
		if !ok {
			continue // no declaration to drift from; unknown claims are claimed_agent_unknown's
		}

		allowedProviders := map[string]bool{}
		allowedHosts := map[string]bool{}
		for _, m := range models {
			if m.Provider != "" {
				allowedProviders[strings.ToLower(m.Provider)] = true
			}
			if m.Endpoint != "" {
				allowedHosts[normalizeHost(m.Endpoint)] = true
			}
		}

		undeclared := map[string]bool{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress {
				continue
			}
			provider, isLLM := matchLLM(e.Resource)
			if !isLLM {
				continue
			}
			if allowedProviders[strings.ToLower(provider)] || allowedHosts[normalizeHost(e.Resource)] {
				continue
			}
			undeclared[provider] = true
		}
		if len(undeclared) == 0 {
			continue
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   model.SeverityHigh,
			Time:       now(),
			Summary: fmt.Sprintf("a process claiming to be %s reached %s, which that agent's Passport does not declare (it declares %s). Either the agent drifted from its own declaration, or something else is using its name",
				claimed,
				strings.Join(sortedKeys(undeclared), ", "),
				strings.Join(sortedKeys(allowedProviders), ", ")),
		})
	}

	sort.Slice(alerts, func(i, j int) bool { return alerts[i].IdentityID < alerts[j].IdentityID })
	return alerts
}
