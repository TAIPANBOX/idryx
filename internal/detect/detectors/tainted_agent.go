package detectors

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// taintBlockWindow bounds how far back a taint_block event still counts
// toward a tainted_agent finding. 30 days matches the "recent behavior"
// horizon idryx already uses for runaway_agent's spendWindow: long enough to
// catch an occasional, slow-drip pattern of attempts, short enough to keep
// the finding about current risk rather than ancient history.
const taintBlockWindow = 30 * 24 * time.Hour

// taintBlockRepeatThreshold is the count at which repeat taint_block events
// escalate a tainted_agent finding to critical (see the severity comment in
// Detect below).
const taintBlockRepeatThreshold = 2

// TaintedAgent flags AI agents with at least one taint_block event: the
// agent-event bus's taint tracker traced a flow from an untrusted/tainted
// source (e.g. a prompt-injected instruction, or attacker-controlled tool
// output) to a sensitive sink and stopped it before it landed (agent-passport
// SPEC §6.2 taint_block, source "tokenfuse"). This is a stronger, more
// precise signal than data_exfiltration's dlp_block: a DLP block is a
// content-pattern match on the data itself and can legitimately false-positive,
// which is why that detector waits for a repeated pattern. A taint block
// instead reflects a traced flow from a known-untrusted origin to a
// known-sensitive sink, so a single occurrence is already actionable
// evidence of an attempted injection/exfiltration: this detector fires on
// the first one rather than waiting for a threshold. Severity still
// escalates on repeat occurrences (a persistent attacker, or a compromised
// agent probing more than one path) and on standing privilege, mirroring
// idryx's existing severity conventions.
type TaintedAgent struct{}

func NewTaintedAgent() *TaintedAgent { return &TaintedAgent{} }

func (d *TaintedAgent) Name() string { return "tainted_agent" }

func (d *TaintedAgent) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		count := 0
		for _, e := range id.Events {
			if e.Type != model.EventTaintBlock {
				continue
			}
			if now().Sub(e.Time) > taintBlockWindow {
				continue
			}
			count++
		}
		if count == 0 {
			continue
		}

		// One blocked taint-tracked action already fires at high; a repeat
		// within the window, or standing privilege/admin access on the
		// agent, raises it to critical.
		sev := model.SeverityHigh
		if count >= taintBlockRepeatThreshold || id.Privileged || id.HasAdmin() {
			sev = model.SeverityCritical
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf(
				"%d taint-tracked action(s) blocked within %s (blocked injection/exfiltration attempt)",
				count, taintBlockWindow),
		})
	}
	return alerts
}
