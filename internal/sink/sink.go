// Package sink delivers alerts to external destinations (Slack, SIEM webhooks).
// Sinks are filtered by a minimum severity so noisy low-severity findings don't
// page anyone.
package sink

import "github.com/TAIPANBOX/idryx/internal/model"

// Sink delivers a batch of alerts to a destination.
type Sink interface {
	// Name identifies the sink in logs.
	Name() string
	// Send delivers the alerts. It should be a no-op for an empty slice.
	Send(alerts []model.Alert) error
}

// AtLeast returns the subset of alerts at or above min severity, preserving
// order. Used by sinks to apply their threshold uniformly.
func AtLeast(alerts []model.Alert, min model.Severity) []model.Alert {
	out := make([]model.Alert, 0, len(alerts))
	for _, a := range alerts {
		if a.Severity >= min {
			out = append(out, a)
		}
	}
	return out
}
