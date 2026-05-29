package detectors

import (
	"fmt"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

const (
	mfaWindow    = 5 * time.Minute
	mfaThreshold = 5 // challenges within the window
)

// MFAFatigue flags a burst of MFA challenges for one identity within a short
// window — the signature of push-bombing / MFA fatigue attacks.
type MFAFatigue struct{}

func NewMFAFatigue() *MFAFatigue { return &MFAFatigue{} }

func (d *MFAFatigue) Name() string { return "mfa_fatigue" }

func (d *MFAFatigue) Detect(g *graph.Store) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		challenges := make([]model.Event, 0)
		for _, e := range id.Events {
			if e.Type == model.EventMFAChallenge {
				challenges = append(challenges, e)
			}
		}
		// Sliding window over chronological challenges.
		start := 0
		for end := range challenges {
			for challenges[end].Time.Sub(challenges[start].Time) > mfaWindow {
				start++
			}
			if end-start+1 >= mfaThreshold {
				sev := model.SeverityHigh
				if id.Privileged {
					sev = model.SeverityCritical
				}
				alerts = append(alerts, model.Alert{
					Detector:   d.Name(),
					IdentityID: id.ID,
					Severity:   sev,
					Time:       challenges[end].Time,
					Summary: fmt.Sprintf("%d MFA challenges within %s",
						end-start+1, mfaWindow),
				})
				break // one alert per identity is enough for Phase 0
			}
		}
	}
	return alerts
}
