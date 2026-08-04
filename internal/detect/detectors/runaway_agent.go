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

// repeatedIncidentThreshold is how many spend incidents inside spendWindow
// stop being a bad day and start being a pattern.
//
// It exists because severity used to depend only on the CONTEXT around an
// agent and not at all on the SIZE of what it did. Measured against a live
// fleet of 999 agents on 2026-08-04, every finding came back `medium` while
// the incident counts behind them ranged from 1 to 73: the number an operator
// needed was printed in the summary and absent from the field they sort by.
// One alert per agent is still the right shape; ranking them all identically
// is not.
//
// Ten rather than a fleet-relative outlier test, deliberately. A relative
// threshold reads well until every agent in the fleet is misbehaving, and
// then it calls the worst offenders normal. This keeps the detector's
// documented promise of being fixed and deterministic.
const repeatedIncidentThreshold = 10

// sustainedIncidentThreshold is where repetition stops being a pattern and
// becomes the whole finding. An agent that hit the same wall fifty times
// inside the window is not misconfigured, it is looping, and nothing else we
// know about it changes what to do next. The live fleet's worst offender sat
// at 73.
const sustainedIncidentThreshold = 50

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
// runtime). Two things raise it, and either works without the other:
//
// By corroborating context:
//   - base: at least one spend event in spendWindow -> medium
//   - >=2 corroborating facts -> high
//   - >=3 corroborating facts -> critical
//
// By the size of the incident, independently:
//   - >=repeatedIncidentThreshold incidents -> at least high
//   - >=sustainedIncidentThreshold incidents -> critical
//
// The second half exists because the first half alone ranked a live fleet of
// 999 agents identically: every finding `medium`, while the incident counts
// behind them ran from 1 to 73. Most agents in a real fleet carry no
// corroborating context at all, so context-only scoring collapses exactly
// where it is needed.
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
		total := totalEvents(counts)
		if total >= repeatedIncidentThreshold {
			reasons = append(reasons, fmt.Sprintf("%d incidents", total))
		}

		sev := model.SeverityMedium
		switch {
		case facts >= 3:
			sev = model.SeverityCritical
		case facts >= 2:
			sev = model.SeverityHigh
		}

		// The size of the incident raises the verdict on its own, rather than
		// counting as one more corroborating fact.
		//
		// It has to work alone, because in a real fleet most agents have no
		// corroborating context at all: nothing privileged, nobody delegated
		// to them, no blast radius. Measured on 999 live agents, that is the
		// common case, and it is exactly the case where an agent doing the
		// same bad thing seventy-three times has to outrank one that did it
		// once. Context can still push the verdict higher; it can no longer
		// be the only thing that does.
		switch {
		case total >= sustainedIncidentThreshold && sev < model.SeverityCritical:
			sev = model.SeverityCritical
		case total >= repeatedIncidentThreshold && sev < model.SeverityHigh:
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

// totalEvents sums a spend-event breakdown. Separate from formatEventCounts
// because the count decides severity and the string only describes it, and
// those two should not share a code path.
func totalEvents(counts map[model.EventType]int) int {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total
}
