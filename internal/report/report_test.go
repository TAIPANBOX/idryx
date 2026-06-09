package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func sampleAlerts() []model.Alert {
	t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	return []model.Alert{
		{Detector: "stale_nhi", IdentityID: "svc-old", Severity: model.SeverityMedium, Time: t0.Add(2 * time.Hour), Summary: "unused 120d"},
		{Detector: "impossible_travel", IdentityID: "alice@x.io", Severity: model.SeverityCritical, Time: t0.Add(time.Hour), Summary: "Kyiv→Sydney in 40m"},
		{Detector: "over_privileged_nhi", IdentityID: "svc-admin", Severity: model.SeverityCritical, Time: t0, Summary: "admin, unused grants"},
		{Detector: "mfa_fatigue", IdentityID: "bob@x.io", Severity: model.SeverityHigh, Time: t0, Summary: "12 pushes in 5m"},
	}
}

func TestSortAlertsSeverityThenTimeThenDetector(t *testing.T) {
	got := sortAlerts(sampleAlerts())
	wantOrder := []string{"over_privileged_nhi", "impossible_travel", "mfa_fatigue", "stale_nhi"}
	for i, d := range wantOrder {
		if got[i].Detector != d {
			t.Fatalf("position %d: want %s, got %s (full: %+v)", i, d, got[i].Detector, got)
		}
	}
}

func TestSortAlertsDoesNotMutateInput(t *testing.T) {
	in := sampleAlerts()
	first := in[0].Detector
	_ = sortAlerts(in)
	if in[0].Detector != first {
		t.Fatal("sortAlerts mutated its input slice")
	}
}

func TestHumanRendersPrioritizedTable(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, sampleAlerts())
	out := buf.String()
	if !strings.Contains(out, "4 alert(s)") {
		t.Errorf("missing count header: %q", out)
	}
	// Critical alerts must render above medium ones.
	if strings.Index(out, "impossible_travel") > strings.Index(out, "stale_nhi") {
		t.Errorf("critical alert rendered below medium:\n%s", out)
	}
	for _, want := range []string{"SEVERITY", "critical", "alice@x.io", "2026-06-01 11:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, nil)
	if !strings.Contains(buf.String(), "No threats detected.") {
		t.Errorf("empty render wrong: %q", buf.String())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleAlerts()); err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 4 {
		t.Fatalf("want 4 alerts, got %d", len(got))
	}
	first := got[0]
	if first["severity"] != "critical" || first["detector"] != "over_privileged_nhi" {
		t.Errorf("unexpected first element: %+v", first)
	}
	if first["time"] != "2026-06-01T10:00:00Z" {
		t.Errorf("time format wrong: %q", first["time"])
	}
}

func TestJSONEmptyIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("empty JSON must be [], got %q", buf.String())
	}
}
