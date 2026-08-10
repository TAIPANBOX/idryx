package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// ClaimedAgentUnattested flags an agent whose Passport declares its identity is
// bound to a workload, and whose only runtime carrier in this graph is a
// process that named itself.
//
// # THE THIRD ANSWER A CLAIM CAN HAVE, AND THE FAMILY IS NOW COMPLETE
//
// `claimed_agent_unknown` is the claim that resolves to nothing.
// `claimed_agent_drift` is the claim that resolves and contradicts what the
// Passport declares. This is the claim that resolves, contradicts nothing, and
// is still the only evidence the agent ever ran: the organisation declared a
// binding (agent-passport SPEC 4.3) and nothing that authenticates identities
// has spoken about the agent at all.
//
// # WHY THE NAME IS NOT THE TAUTOLOGY IT LOOKS LIKE
//
// Every claim is unattested. SPEC 3.3 says so and this detector does not
// rediscover it. The finding is about the PAIR: an organisation that declared a
// strong binding, and a graph in which the only runtime evidence of that agent
// is exactly the kind of statement the binding exists to make unnecessary.
//
// # WHAT IS NOT OBSERVABLE, SO THAT NOBODY READS THIS AS MORE
//
// The binding itself is never checked and cannot be. idryx has no connector to
// any attestation plane (SPIRE, an OIDC issuer, an mTLS CA), and reading a
// handshake would be reading what the application wrote into its socket, which
// SECURITY.md forbids permanently for the same reason JA3/JA4 was decided
// against. So this compares two facts already in the graph and never verifies a
// method.
//
// A bus event under the established name is likewise NOT proof the declared
// method was exercised. A plane authenticates with its own credential, not with
// the Passport's `attestation.method`. What such an event proves is that some
// infrastructure established the identity, which is enough to make this
// detector silent: something other than the process itself vouched for the
// name.
//
// # THE PRECONDITION, BECAUSE ONE SILENCE WOULD OTHERWISE BE TWO FACTS
//
// It judges nothing unless some bus producer feeds this graph at all. Only the
// agent-event connector sets `Event.Source`, so that is the test. Without it,
// "nothing established this agent" is true of every agent in every
// sensor-only run and means only that no bus file was loaded, which is the
// silent-zero shape this repository keeps paying for.
//
// One reading stays open even with the precondition met, and the wording keeps
// it: an agent may be served by a plane whose journal simply was not loaded
// into this run.
//
// Severity is medium, and high when the established identity is privileged or
// holds admin, mirroring what attestation_missing does with the same posture.
type ClaimedAgentUnattested struct{}

func NewClaimedAgentUnattested() *ClaimedAgentUnattested { return &ClaimedAgentUnattested{} }

func (d *ClaimedAgentUnattested) Name() string { return "claimed_agent_unattested" }

func (d *ClaimedAgentUnattested) Detect(g graph.Reader) []model.Alert {
	identities := g.Identities()

	if !carriesBusEvidence(identities) {
		return nil
	}

	// The established side, indexed by its own name, and only those that
	// declare a binding. An agent whose Passport says `none`, or carries no
	// attestation block at all, has declared nothing to be at odds with: that
	// posture is attestation_missing's and bom_incomplete's, and reporting it
	// here would be the same fact under a second name.
	declared := map[string]*model.Identity{}
	for _, id := range identities {
		if ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		if id.Attestation == "" || id.Attestation == "none" {
			continue
		}
		declared[id.ID] = id
	}
	if len(declared) == 0 {
		return nil
	}

	var alerts []model.Alert
	for _, id := range identities {
		if !ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		name := strings.TrimPrefix(id.ID, ebpfcapture.ClaimedPrefix)
		established, ok := declared[name]
		if !ok {
			continue // no declared binding to be the only carrier of
		}
		if len(established.Events) > 0 {
			// Something other than the process itself has spoken about this
			// agent. That is not proof the declared method was exercised, and
			// it is enough: the name is carried by more than a self-declaration.
			continue
		}

		sev := model.SeverityMedium
		if established.Privileged || established.HasAdmin() {
			sev = model.SeverityHigh
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf("a process claiming to be %s was observed %d time(s), and that agent's Passport declares its identity is bound to a workload (attestation=%s); nothing that authenticates identities has spoken about this agent in this graph. Either the attested workload runs where no plane feeding this graph can see it, or the name is being worn by something the binding does not cover",
				name, len(id.Events), attestationLabel(established.Attestation)),
		})
	}

	sort.Slice(alerts, func(i, j int) bool { return alerts[i].IdentityID < alerts[j].IdentityID })
	return alerts
}

// carriesBusEvidence reports whether any agent-event producer contributed to
// this graph. Only internal/ingest/tokenfuse sets Event.Source, so a non-empty
// one is that connector's fingerprint and nothing else's.
func carriesBusEvidence(identities []*model.Identity) bool {
	for _, id := range identities {
		if ebpfcapture.IsClaimed(id.ID) {
			continue
		}
		for _, e := range id.Events {
			if e.Source != "" {
				return true
			}
		}
	}
	return false
}
