package report

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestSortAlertsBreaksTiesByDetector: same severity and time order by
// detector name, so two runs over one input print one table.
func TestSortAlertsBreaksTiesByDetector(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	in := []model.Alert{
		{Detector: "stale_nhi", Severity: model.SeverityHigh, Time: at},
		{Detector: "bom_incomplete", Severity: model.SeverityHigh, Time: at},
		{Detector: "mfa_fatigue", Severity: model.SeverityHigh, Time: at},
	}
	got := sortAlerts(in)
	want := []string{"bom_incomplete", "mfa_fatigue", "stale_nhi"}
	for i, a := range got {
		if a.Detector != want[i] {
			t.Fatalf("order = %v, want %v", []string{got[0].Detector, got[1].Detector, got[2].Detector}, want)
		}
	}
	if in[0].Detector != "stale_nhi" {
		t.Error("sortAlerts reordered the caller's slice")
	}
}
