package ingest

import (
	"encoding/json"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// ctRecord is the subset of an AWS CloudTrail record idryx reads. CloudTrail
// exports records under a "Records" array.
type ctRecord struct {
	EventTime    string `json:"eventTime"`
	EventName    string `json:"eventName"`
	SourceIP     string `json:"sourceIPAddress"`
	UserAgent    string `json:"userAgent"`
	ErrorCode    string `json:"errorCode"`
	UserIdentity struct {
		ARN  string `json:"arn"`
		Type string `json:"type"`
	} `json:"userIdentity"`
}

type ctEnvelope struct {
	Records []ctRecord `json:"Records"`
}

// CloudTrail parses an AWS CloudTrail log into normalized events. ConsoleLogin
// maps to a login event; other API calls are recorded as generic events so the
// graph captures NHI/role activity for later phases.
func CloudTrail(data []byte) ([]model.Event, error) {
	var env ctEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}

	out := make([]model.Event, 0, len(env.Records))
	for _, r := range env.Records {
		t, err := time.Parse(time.RFC3339, r.EventTime)
		if err != nil {
			continue
		}
		id := r.UserIdentity.ARN
		if id == "" {
			id = r.UserIdentity.Type
		}
		etype := model.EventOther
		if r.EventName == "ConsoleLogin" {
			etype = model.EventLogin
		}
		outcome := "SUCCESS"
		if r.ErrorCode != "" {
			outcome = "FAILURE"
		}
		out = append(out, model.Event{
			Time:       t,
			IdentityID: id,
			Type:       etype,
			Outcome:    outcome,
			IP:         r.SourceIP,
			Device:     r.UserAgent,
		})
	}
	return out, nil
}
