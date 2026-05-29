package detect_test

import (
	"os"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/detect"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestDetectorsOnFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/events.json")
	if err != nil {
		t.Fatal(err)
	}
	events, err := ingest.Okta(data)
	if err != nil {
		t.Fatal(err)
	}

	g := graph.New(map[string]bool{
		"bob@example.com":   true,
		"carol@example.com": true,
	})
	for _, e := range events {
		g.AddEvent(e)
	}

	ds := []detect.Detector{
		detectors.NewImpossibleTravel(),
		detectors.NewMFAFatigue(),
		detectors.NewNewDevice(),
	}
	var alerts []model.Alert
	for _, d := range ds {
		alerts = append(alerts, d.Detect(g)...)
	}

	got := map[string]bool{}
	for _, a := range alerts {
		got[a.Detector+"/"+a.IdentityID] = true
	}

	want := []string{
		"impossible_travel/alice@example.com",
		"mfa_fatigue/bob@example.com",
		"new_device/carol@example.com",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected alert %q, not found", w)
		}
	}

	// dave is a normal single login — must not trigger anything.
	for _, a := range alerts {
		if a.IdentityID == "dave@example.com" {
			t.Errorf("unexpected alert for dave: %s %s", a.Detector, a.Summary)
		}
	}
	// alice is not privileged — impossible travel should be high, not critical.
	for _, a := range alerts {
		if a.IdentityID == "alice@example.com" && a.Severity != model.SeverityHigh {
			t.Errorf("alice severity = %v, want high", a.Severity)
		}
	}
}
