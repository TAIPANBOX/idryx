// Package baseline builds per-identity behavioral baselines from past events
// and scores new events against them. This is the core differentiator: what is
// normal for one identity is anomalous for another. Scoring is deterministic —
// frequency statistics, never an LLM in the path.
package baseline

import (
	"sort"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Profile is the learned normal behavior of a single identity.
type Profile struct {
	IdentityID    string
	Countries     map[string]int // country -> login count
	Devices       map[string]int // device -> login count
	HourHistogram [24]int        // logins per UTC hour
	TotalLogins   int
	FirstSeen     time.Time
	LastSeen      time.Time
}

// NewProfile returns an empty profile for an identity.
func NewProfile(identityID string) *Profile {
	return &Profile{
		IdentityID: identityID,
		Countries:  map[string]int{},
		Devices:    map[string]int{},
	}
}

// Observe folds one successful login into the profile. Non-login or failed
// events are ignored — they are scored against the baseline, not part of it.
func (p *Profile) Observe(e model.Event) {
	if e.Type != model.EventLogin || e.Outcome != "SUCCESS" {
		return
	}
	if p.TotalLogins == 0 || e.Time.Before(p.FirstSeen) {
		p.FirstSeen = e.Time
	}
	if e.Time.After(p.LastSeen) {
		p.LastSeen = e.Time
	}
	p.TotalLogins++
	if e.Country != "" {
		p.Countries[e.Country]++
	}
	if e.Device != "" {
		p.Devices[e.Device]++
	}
	p.HourHistogram[e.Time.UTC().Hour()]++
}

// Build computes a profile from all of an identity's events. Use this for a
// static baseline; for scoring a stream where each event is judged against the
// past, build incrementally with NewProfile + Observe.
func Build(id *model.Identity) *Profile {
	p := NewProfile(id.ID)
	for _, e := range id.Events {
		p.Observe(e)
	}
	return p
}

// Score rates how unusual an event is for this profile, 0.0 (normal) to 1.0
// (highly anomalous). A profile with too few logins is not yet trustworthy and
// returns 0 to avoid false positives during the learning period.
const minLoginsToScore = 5

func (p *Profile) Score(e model.Event) float64 {
	if p.TotalLogins < minLoginsToScore {
		return 0
	}

	var score float64
	// Country never seen before is the strongest single signal.
	if e.Country != "" && p.Countries[e.Country] == 0 {
		score += 0.5
	}
	// Device never seen before.
	if e.Device != "" && p.Devices[e.Device] == 0 {
		score += 0.3
	}
	// Login hour that the identity has never been active in.
	if e.Type == model.EventLogin && p.HourHistogram[e.Time.UTC().Hour()] == 0 {
		score += 0.2
	}

	if score > 1 {
		score = 1
	}
	return score
}

// RareCountries returns countries seen in at most maxCount logins, sorted by
// count then name — useful for explaining why an event scored high.
func (p *Profile) RareCountries(maxCount int) []string {
	var out []string
	for c, n := range p.Countries {
		if n <= maxCount {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if p.Countries[out[i]] != p.Countries[out[j]] {
			return p.Countries[out[i]] < p.Countries[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
