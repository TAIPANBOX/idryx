package detectors

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// spendWindow bounds how far back a tokenfuse spend incident still counts
// toward a runaway_agent finding. 30 days matches the "recent behavior"
// horizon idryx already uses elsewhere (e.g. staleAfter's 90-day rotation
// window is the long end of that spectrum; spend incidents are acute, so a
// shorter window keeps the finding about current risk, not history).
const spendWindow = 30 * 24 * time.Hour

// blastRadiusThreshold is the number of de-duplicated effective permissions
// (graph.BlastRadius) at or above which an agent's reach counts as a
// corroborating fact for runaway_agent. 5 is a deliberately low bar: an
// agent that is already burning budget and can additionally reach five or
// more permissions across its delegation chain is worth a human look
// regardless of which five they are — over_privileged_nhi/excessive_agency
// judge the permissions themselves; this detector only judges reach.
const blastRadiusThreshold = 5

// spendEventTypes is the tokenfuse spend/runaway incident taxonomy this
// detector correlates (agent-passport SPEC §6.2, source "tokenfuse").
// dlp_block/taint_block/mcp_drift are also tokenfuse types but are not spend
// signals, so they are intentionally excluded here.
var spendEventTypes = map[model.EventType]bool{
	model.EventBudgetExhausted: true,
	model.EventSustainedLoop:   true,
	model.EventSpendSpike:      true,
	model.EventFanoutExplosion: true,
	model.EventBreakerTripped:  true,
}

// RunawayAgent correlates TokenFuse spend/runaway incidents with everything
// else idryx already knows about the agent that triggered them: standing
// privilege, delegation depth, identity attestation, and blast radius. It
// produces one finding per agent (not per event) so the output is a single,
// escalating severity that reflects how much corroborating context
// surrounds the spend signal — not a flood of one alert per incident.
//
// Severity mapping (fixed, deterministic — documented here, not tunable at
// runtime):
//   - base: at least one spend event in spendWindow -> medium
//   - >=2 corroborating facts -> high
//   - >=3 corroborating facts -> critical
//
// Corroborating facts (each contributes at most one to the count, order
// fixed for a deterministic summary):
//  1. privileged/admin permission present: id.Privileged || id.HasAdmin()
//  2. delegation chain length >= 2 (graph.WalkDelegationChain(id) has more
//     than the identity itself): the agent is acting on behalf of at least
//     one principal, not autonomous
//  3. unattested identity: Attestation is "" or "none" (agent-passport SPEC
//     §4.3 — "none" is the honest default, but still worth flagging on an
//     agent already showing a spend incident)
//  4. blast radius (graph.BlastRadius, de-duplicated by permission name)
//     at or above blastRadiusThreshold
type RunawayAgent struct{}

func NewRunawayAgent() *RunawayAgent { return &RunawayAgent{} }

func (d *RunawayAgent) Name() string { return "runaway_agent" }

func (d *RunawayAgent) Detect(g graph.Reader) []model.Alert {
	index := map[string]*model.Identity{}
	for _, id := range g.Identities() {
		index[id.ID] = id
	}

	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}

		counts := map[model.EventType]int{}
		for _, e := range id.Events {
			if !spendEventTypes[e.Type] {
				continue
			}
			if now().Sub(e.Time) > spendWindow {
				continue
			}
			counts[e.Type]++
		}
		if len(counts) == 0 {
			continue
		}

		chain := graph.WalkDelegationChain(index, id.ID)
		blast := graph.BlastRadius(index, id.ID)
		unattested := id.Attestation == "" || id.Attestation == "none"

		facts := 0
		var reasons []string
		if id.Privileged || id.HasAdmin() {
			facts++
			reasons = append(reasons, "privileged")
		}
		if len(chain) >= 2 {
			facts++
			reasons = append(reasons, fmt.Sprintf("delegation depth %d", len(chain)-1))
		}
		if unattested {
			facts++
			reasons = append(reasons, "unattested")
		}
		if len(blast) >= blastRadiusThreshold {
			facts++
			reasons = append(reasons, fmt.Sprintf("blast radius %d", len(blast)))
		}

		sev := model.SeverityMedium
		switch {
		case facts >= 3:
			sev = model.SeverityCritical
		case facts >= 2:
			sev = model.SeverityHigh
		}
		if len(reasons) == 0 {
			reasons = []string{"none"}
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf(
				"agent spend incident: %s; delegation depth %d; attestation=%s; blast radius %d permission(s); corroborating: %s",
				formatEventCounts(counts), len(chain)-1, attestationLabel(id.Attestation), len(blast), strings.Join(reasons, ", ")),
		})
	}
	// g.Identities() is documented to return identities sorted by ID for
	// the in-memory/Postgres backends, but graph.Reader itself makes no such
	// guarantee — sort explicitly so runaway_agent's output order is
	// deterministic for any backend.
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].IdentityID < alerts[j].IdentityID })
	return alerts
}

// formatEventCounts renders a spend-event breakdown as "type=count, ..." in
// a fixed (sorted) order, since Go map iteration order is randomized and the
// summary must be identical across repeated runs on the same input.
func formatEventCounts(counts map[model.EventType]int) string {
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, string(t))
	}
	sort.Strings(types)
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, counts[model.EventType(t)]))
	}
	return strings.Join(parts, ", ")
}

// attestationLabel renders an Identity.Attestation value for a Summary
// string, spelling out the zero value instead of printing an empty segment.
func attestationLabel(a string) string {
	if a == "" {
		return "unset"
	}
	return a
}
