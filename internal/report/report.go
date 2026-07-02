// Package report renders alerts as human-readable or JSON output.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// sortAlerts orders alerts by severity (desc), then time, then detector for a
// stable, prioritized view.
func sortAlerts(alerts []model.Alert) []model.Alert {
	out := append([]model.Alert(nil), alerts...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.Before(out[j].Time)
		}
		return out[i].Detector < out[j].Detector
	})
	return out
}

// Human writes a prioritized table of alerts.
func Human(w io.Writer, alerts []model.Alert) {
	alerts = sortAlerts(alerts)
	fmt.Fprintf(w, "idryx: %d alert(s)\n\n", len(alerts))
	if len(alerts) == 0 {
		fmt.Fprintln(w, "No threats detected.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tDETECTOR\tIDENTITY\tTIME\tDETAIL")
	for _, a := range alerts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			a.Severity, a.Detector, a.IdentityID,
			a.Time.UTC().Format("2006-01-02 15:04Z"), a.Summary)
	}
	_ = tw.Flush()
}

type jsonAlert struct {
	Detector   string `json:"detector"`
	IdentityID string `json:"identity"`
	Severity   string `json:"severity"`
	Time       string `json:"time"`
	Summary    string `json:"summary"`
}

// JSON writes alerts as a JSON array.
func JSON(w io.Writer, alerts []model.Alert) error {
	alerts = sortAlerts(alerts)
	out := make([]jsonAlert, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, jsonAlert{
			Detector:   a.Detector,
			IdentityID: a.IdentityID,
			Severity:   a.Severity.String(),
			Time:       a.Time.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:    a.Summary,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
