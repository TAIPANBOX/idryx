package detectors

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// dlpBlockWindow bounds how far back a dlp_block event still counts toward a
// data_exfiltration finding. 24 hours keeps the finding about one live
// episode of blocked attempts (an operational day of agent activity),
// shorter than runaway_agent's 30-day spendWindow: a DLP block is itself
// already an acute, in-the-moment security event, not a slow-burn spend
// trend to watch over weeks.
const dlpBlockWindow = 24 * time.Hour

// dlpBlockThreshold is the number of dlp_block events within dlpBlockWindow
// required to fire. A single DLP block can be a benign false positive (a
// content classifier over-matching on innocuous data); a repeated pattern on
// the same identity is what turns "noise" into "this agent keeps trying to
// move data it shouldn't" (mirrors mfa_fatigue's window+threshold shape,
// tuned for a slower cadence than an MFA-push burst since DLP evaluations
// happen per agent action, not per second).
const dlpBlockThreshold = 3

// DataExfiltration flags AI agents that accumulate DLP-blocked actions within
// dlpBlockWindow: each dlp_block event is a prevented attempt to move
// sensitive data out (agent-passport SPEC §6.2, source "tokenfuse").
// internal/ingest/tokenfuse has parsed this event type since the connector
// was written, but before this detector no consumer read it: it never
// surfaced as a finding.
type DataExfiltration struct{}

func NewDataExfiltration() *DataExfiltration { return &DataExfiltration{} }

func (d *DataExfiltration) Name() string { return "data_exfiltration" }

func (d *DataExfiltration) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsAgent() {
			continue
		}
		count := 0
		for _, e := range id.Events {
			if e.Type != model.EventDLPBlock {
				continue
			}
			if now().Sub(e.Time) > dlpBlockWindow {
				continue
			}
			count++
		}
		if count < dlpBlockThreshold {
			continue
		}

		// Severity scales with count: crossing the threshold is already
		// worth a human look (high); a count at or beyond double the
		// threshold, or standing privilege/admin access on the agent
		// itself, raises it to critical, the same privilege escalation
		// idryx already applies elsewhere (mfa_fatigue, stale_nhi).
		sev := model.SeverityHigh
		if count >= dlpBlockThreshold*2 || id.Privileged || id.HasAdmin() {
			sev = model.SeverityCritical
		}

		alerts = append(alerts, model.Alert{
			Detector:   d.Name(),
			IdentityID: id.ID,
			Severity:   sev,
			Time:       now(),
			Summary: fmt.Sprintf(
				"%d DLP-blocked action(s) within %s (possible data exfiltration attempt)",
				count, dlpBlockWindow),
		})
	}
	return alerts
}
