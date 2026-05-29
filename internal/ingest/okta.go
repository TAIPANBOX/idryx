// Package ingest converts source-specific logs into normalized model.Events.
package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// oktaEvent is the subset of an Okta System Log entry that idryx Phase 0 reads.
type oktaEvent struct {
	Published string `json:"published"`
	EventType string `json:"eventType"`
	Outcome   struct {
		Result string `json:"result"`
	} `json:"outcome"`
	Actor struct {
		AlternateID string `json:"alternateId"`
	} `json:"actor"`
	Client struct {
		IPAddress string `json:"ipAddress"`
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
		GeographicalContext struct {
			City        string `json:"city"`
			Country     string `json:"country"`
			Geolocation struct {
				Lat float64 `json:"lat"`
				Lon float64 `json:"lon"`
			} `json:"geolocation"`
		} `json:"geographicalContext"`
	} `json:"client"`
}

// Okta parses an Okta System Log JSON array into normalized events.
func Okta(data []byte) ([]model.Event, error) {
	var raw []oktaEvent
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(raw))
	for _, r := range raw {
		t, err := time.Parse(time.RFC3339, r.Published)
		if err != nil {
			continue // skip entries without a usable timestamp
		}
		out = append(out, model.Event{
			Time:       t,
			IdentityID: r.Actor.AlternateID,
			Type:       mapType(r.EventType),
			Outcome:    r.Outcome.Result,
			IP:         r.Client.IPAddress,
			City:       r.Client.GeographicalContext.City,
			Country:    r.Client.GeographicalContext.Country,
			Lat:        r.Client.GeographicalContext.Geolocation.Lat,
			Lon:        r.Client.GeographicalContext.Geolocation.Lon,
			Device:     r.Client.UserAgent.RawUserAgent,
		})
	}
	return out, nil
}

// mapType normalizes an Okta eventType into a model.EventType. MFA is checked
// first because some MFA events also contain "authentication".
func mapType(t string) model.EventType {
	switch {
	case strings.Contains(t, "push"),
		strings.Contains(t, "factor"),
		strings.Contains(t, ".mfa."):
		return model.EventMFAChallenge
	case strings.Contains(t, "session.start"),
		strings.HasPrefix(t, "user.authentication"):
		return model.EventLogin
	default:
		return model.EventOther
	}
}
