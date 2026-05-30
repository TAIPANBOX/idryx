package detectors

import (
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/baseline"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// anomalyThreshold is the baseline score above which an event becomes an alert.
const anomalyThreshold = 0.6

// BehaviorAnomaly scores each identity's latest events against its learned
// baseline and alerts on deviations. This is the engine that later extends to
// NHIs and agents: same scoring, different identity types.
type BehaviorAnomaly struct{}

func NewBehaviorAnomaly() *BehaviorAnomaly { return &BehaviorAnomaly{} }

func (d *BehaviorAnomaly) Name() string { return "behavior_anomaly" }

func (d *BehaviorAnomaly) Detect(g *graph.Store) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		// Score each login against the baseline of everything that came before
		// it, then fold it in. Identities() returns events in chronological
		// order, so this is a true "deviation from prior normal" check.
		p := baseline.NewProfile(id.ID)
		for _, e := range id.Events {
			if e.Type != model.EventLogin || e.Outcome != "SUCCESS" {
				continue
			}
			score := p.Score(e)
			p.Observe(e)
			if score < anomalyThreshold {
				continue
			}
			sev := model.SeverityMedium
			if score >= 0.8 {
				sev = model.SeverityHigh
			}
			if id.Privileged && sev < model.SeverityCritical {
				sev++
			}
			alerts = append(alerts, model.Alert{
				Detector:   d.Name(),
				IdentityID: id.ID,
				Severity:   sev,
				Time:       e.Time,
				Summary: fmt.Sprintf("anomaly score %.2f: login from %s (%s) deviates from baseline",
					score, e.Country, e.Device),
			})
		}
	}
	return alerts
}
