package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// login returns a successful login event at 09:00 UTC on the given day offset
// from the fixed test clock, with the given country and device.
func login(id string, day int, country, device string) model.Event {
	return model.Event{
		IdentityID: id,
		Type:       model.EventLogin,
		Outcome:    "SUCCESS",
		Time:       fixedNow().Add(-30*24*time.Hour + time.Duration(day)*24*time.Hour + 9*time.Hour),
		Country:    country,
		Device:     device,
	}
}

func TestBehaviorAnomaly(t *testing.T) {
	withFixedNow(t)
	g := graph.New(map[string]bool{"admin@x.com": true})

	// bob: 5 baseline logins, then a login with new country + new device + new
	// hour (03:00 UTC) — score 1.0 -> high.
	for i := 0; i < 5; i++ {
		g.AddEvent(login("bob@x.com", i, "US", "laptop-1"))
	}
	g.AddEvent(model.Event{
		IdentityID: "bob@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time:    fixedNow().Add(-10*24*time.Hour + 3*time.Hour),
		Country: "RU", Device: "tor-browser",
	})

	// admin: same full anomaly, but privileged -> severity bumped to critical.
	for i := 0; i < 5; i++ {
		g.AddEvent(login("admin@x.com", i, "US", "laptop-2"))
	}
	g.AddEvent(model.Event{
		IdentityID: "admin@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time:    fixedNow().Add(-10*24*time.Hour + 3*time.Hour),
		Country: "RU", Device: "tor-browser",
	})

	// carol: new country + new hour but a known device — score 0.7 -> medium.
	for i := 0; i < 5; i++ {
		g.AddEvent(login("carol@x.com", i, "US", "laptop-3"))
	}
	g.AddEvent(model.Event{
		IdentityID: "carol@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time:    fixedNow().Add(-10*24*time.Hour + 3*time.Hour),
		Country: "FR", Device: "laptop-3",
	})

	// dave: benign — every login matches the established baseline.
	for i := 0; i < 8; i++ {
		g.AddEvent(login("dave@x.com", i, "US", "laptop-4"))
	}

	// erin: new country only (known device, known hour) — score 0.5 stays
	// below the 0.6 threshold.
	for i := 0; i < 5; i++ {
		g.AddEvent(login("erin@x.com", i, "US", "laptop-5"))
	}
	g.AddEvent(login("erin@x.com", 10, "FR", "laptop-5"))

	// frank: still in the learning period — only 3 prior logins, so even a
	// wildly different login must not score.
	for i := 0; i < 3; i++ {
		g.AddEvent(login("frank@x.com", i, "US", "laptop-6"))
	}
	g.AddEvent(model.Event{
		IdentityID: "frank@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time:    fixedNow().Add(-10*24*time.Hour + 3*time.Hour),
		Country: "RU", Device: "tor-browser",
	})

	got := detect(NewBehaviorAnomaly(), g)

	if a, ok := got["bob@x.com"]; !ok {
		t.Error("expected bob's full anomaly to be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("bob severity = %v, want high", a.Severity)
	}

	if a, ok := got["admin@x.com"]; !ok {
		t.Error("expected privileged admin's anomaly to be flagged")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("admin severity = %v, want critical (privileged bump)", a.Severity)
	}

	if a, ok := got["carol@x.com"]; !ok {
		t.Error("expected carol's new-country+new-hour login to be flagged")
	} else if a.Severity != model.SeverityMedium {
		t.Errorf("carol severity = %v, want medium", a.Severity)
	}

	if _, ok := got["dave@x.com"]; ok {
		t.Error("dave's logins match his baseline; should not alert")
	}
	if _, ok := got["erin@x.com"]; ok {
		t.Error("erin's new-country-only login scores below threshold; should not alert")
	}
	if _, ok := got["frank@x.com"]; ok {
		t.Error("frank is still in the baseline learning period; should not alert")
	}
}

func TestBehaviorAnomalyIgnoresFailedLogins(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	for i := 0; i < 5; i++ {
		g.AddEvent(login("gwen@x.com", i, "US", "laptop-1"))
	}
	// Anomalous but FAILED login — scored events must be successful logins.
	g.AddEvent(model.Event{
		IdentityID: "gwen@x.com", Type: model.EventLogin, Outcome: "FAILURE",
		Time:    fixedNow().Add(-10*24*time.Hour + 3*time.Hour),
		Country: "RU", Device: "tor-browser",
	})

	if got := detect(NewBehaviorAnomaly(), g); len(got) != 0 {
		t.Errorf("failed logins must not be scored, got %v", got)
	}
}
