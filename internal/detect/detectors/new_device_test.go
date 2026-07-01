package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func deviceLogin(id string, at time.Time, device string) model.Event {
	return model.Event{
		IdentityID: id,
		Type:       model.EventLogin,
		Outcome:    "SUCCESS",
		Time:       at,
		Device:     device,
	}
}

func TestNewDevice(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-24 * time.Hour)
	g := graph.New(map[string]bool{
		"admin@x.com": true,
		"carol@x.com": true,
		"dana@x.com":  true,
		"erin@x.com":  true,
	})

	// admin (privileged): established device, then a new one -> high.
	g.AddEvent(deviceLogin("admin@x.com", base, "laptop-1"))
	g.AddEvent(deviceLogin("admin@x.com", base.Add(1*time.Hour), "laptop-1"))
	g.AddEvent(deviceLogin("admin@x.com", base.Add(2*time.Hour), "phone-7"))

	// bob (not privileged): same new-device pattern, but the detector only
	// watches privileged identities.
	g.AddEvent(deviceLogin("bob@x.com", base, "laptop-2"))
	g.AddEvent(deviceLogin("bob@x.com", base.Add(1*time.Hour), "phone-9"))

	// carol (privileged): always the same device -> no alert.
	g.AddEvent(deviceLogin("carol@x.com", base, "laptop-3"))
	g.AddEvent(deviceLogin("carol@x.com", base.Add(1*time.Hour), "laptop-3"))

	// dana (privileged): first-ever login — the first device is the baseline,
	// not an alert.
	g.AddEvent(deviceLogin("dana@x.com", base, "laptop-4"))

	// erin (privileged): the second device only appears on a FAILED login and
	// an event with no device fingerprint; neither counts.
	g.AddEvent(deviceLogin("erin@x.com", base, "laptop-5"))
	g.AddEvent(model.Event{
		IdentityID: "erin@x.com", Type: model.EventLogin, Outcome: "FAILURE",
		Time: base.Add(1 * time.Hour), Device: "evil-box",
	})
	g.AddEvent(model.Event{
		IdentityID: "erin@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time: base.Add(2 * time.Hour),
	})

	got := detect(NewNewDevice(), g)

	if a, ok := got["admin@x.com"]; !ok {
		t.Error("expected privileged admin's new device to be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("admin severity = %v, want high", a.Severity)
	}

	if _, ok := got["bob@x.com"]; ok {
		t.Error("non-privileged identity must not be flagged by new_device")
	}
	if _, ok := got["carol@x.com"]; ok {
		t.Error("repeated logins from a known device should not alert")
	}
	if _, ok := got["dana@x.com"]; ok {
		t.Error("first-ever device is the baseline; should not alert")
	}
	if _, ok := got["erin@x.com"]; ok {
		t.Error("failed logins and device-less events must not trigger new_device")
	}
}

func TestNewDeviceKnownDeviceAfterAlert(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-24 * time.Hour)
	g := graph.New(map[string]bool{"admin@x.com": true})

	// One alert for the first sighting of phone-7; the later return to it is
	// already known and must not alert again.
	g.AddEvent(deviceLogin("admin@x.com", base, "laptop-1"))
	g.AddEvent(deviceLogin("admin@x.com", base.Add(1*time.Hour), "phone-7"))
	g.AddEvent(deviceLogin("admin@x.com", base.Add(2*time.Hour), "laptop-1"))
	g.AddEvent(deviceLogin("admin@x.com", base.Add(3*time.Hour), "phone-7"))

	alerts := NewNewDevice().Detect(g)
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one alert for one new device, got %d", len(alerts))
	}
	if alerts[0].Time != base.Add(1*time.Hour) {
		t.Errorf("alert time = %v, want the first phone-7 login at %v", alerts[0].Time, base.Add(1*time.Hour))
	}
}
