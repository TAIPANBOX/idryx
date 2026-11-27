package baseline

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestObserveLearnsOnlyFromSuccessfulLogins: a failed login or a non-login
// event is scored against the baseline, never folded into it, so an attacker
// cannot teach the profile their country by failing to log in from it.
func TestObserveLearnsOnlyFromSuccessfulLogins(t *testing.T) {
	p := NewProfile("amy@x.com")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.Observe(model.Event{Type: model.EventLogin, Outcome: "FAILURE", Country: "KP", Time: at})
	p.Observe(model.Event{Type: model.EventMFAChallenge, Outcome: "SUCCESS", Country: "KP", Time: at})
	if p.TotalLogins != 0 || len(p.Countries) != 0 {
		t.Fatalf("profile learned from non-baseline events: logins=%d countries=%v", p.TotalLogins, p.Countries)
	}
	p.Observe(model.Event{Type: model.EventLogin, Outcome: "SUCCESS", Country: "GB", Time: at})
	if p.TotalLogins != 1 || p.Countries["GB"] != 1 {
		t.Errorf("a successful login was not learned: logins=%d countries=%v", p.TotalLogins, p.Countries)
	}
}
