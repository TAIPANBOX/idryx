package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func mfaChallenge(id string, at time.Time) model.Event {
	return model.Event{
		IdentityID: id,
		Type:       model.EventMFAChallenge,
		Time:       at,
	}
}

func TestMFAFatigue(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-1 * time.Hour)
	g := graph.New(map[string]bool{"admin@x.com": true})

	// bob: 5 challenges in 4 minutes — classic push-bombing burst -> high.
	for i := 0; i < 5; i++ {
		g.AddEvent(mfaChallenge("bob@x.com", base.Add(time.Duration(i)*time.Minute)))
	}

	// admin: same burst, but privileged -> critical.
	for i := 0; i < 5; i++ {
		g.AddEvent(mfaChallenge("admin@x.com", base.Add(time.Duration(i)*time.Minute)))
	}

	// carol: 5 challenges spread 6 minutes apart — never 5 within the window.
	for i := 0; i < 5; i++ {
		g.AddEvent(mfaChallenge("carol@x.com", base.Add(time.Duration(i)*6*time.Minute)))
	}

	// dave: a burst of successful logins, not MFA challenges — wrong event type.
	for i := 0; i < 5; i++ {
		g.AddEvent(model.Event{
			IdentityID: "dave@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
			Time: base.Add(time.Duration(i) * time.Minute),
		})
	}

	got := detect(NewMFAFatigue(), g)

	if a, ok := got["bob@x.com"]; !ok {
		t.Error("expected bob's MFA burst to be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("bob severity = %v, want high", a.Severity)
	}

	if a, ok := got["admin@x.com"]; !ok {
		t.Error("expected privileged admin's MFA burst to be flagged")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("admin severity = %v, want critical (privileged)", a.Severity)
	}

	if _, ok := got["carol@x.com"]; ok {
		t.Error("carol's spread-out challenges should not alert")
	}
	if _, ok := got["dave@x.com"]; ok {
		t.Error("login events must not count as MFA challenges")
	}
}

func TestMFAFatigueJustUnderThreshold(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-1 * time.Hour)
	g := graph.New(nil)

	// 4 challenges within the window — one short of the threshold.
	for i := 0; i < 4; i++ {
		g.AddEvent(mfaChallenge("erin@x.com", base.Add(time.Duration(i)*time.Minute)))
	}

	if got := detect(NewMFAFatigue(), g); len(got) != 0 {
		t.Errorf("4 challenges are below the threshold of 5, got %v", got)
	}
}

func TestMFAFatigueOneAlertPerIdentity(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-1 * time.Hour)
	g := graph.New(nil)

	// A long burst that satisfies the window many times over must still
	// produce a single alert.
	for i := 0; i < 20; i++ {
		g.AddEvent(mfaChallenge("frank@x.com", base.Add(time.Duration(i)*30*time.Second)))
	}

	alerts := NewMFAFatigue().Detect(g)
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one alert per identity, got %d", len(alerts))
	}
	if alerts[0].IdentityID != "frank@x.com" {
		t.Errorf("alert identity = %q, want frank@x.com", alerts[0].IdentityID)
	}
}
