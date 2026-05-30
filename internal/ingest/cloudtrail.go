package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// ctRecord is the subset of an AWS CloudTrail record idryx reads. CloudTrail
// exports records under a "Records" array.
type ctRecord struct {
	EventTime    string `json:"eventTime"`
	EventName    string `json:"eventName"`
	EventSource  string `json:"eventSource"`
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

// CloudTrailUsage returns a map of normalized principal ARN to the set of AWS
// service prefixes (e.g. "s3", "ec2") that principal was observed calling.
// Assumed-role session ARNs are normalized to their base role ARN so they match
// identities produced by AWSIAM.
func CloudTrailUsage(data []byte) (map[string]map[string]bool, error) {
	var env ctEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]bool)
	for _, r := range env.Records {
		arn := normalizeARN(r.UserIdentity.ARN)
		if arn == "" || r.EventSource == "" {
			continue
		}
		svc := serviceFromEventSource(r.EventSource)
		if out[arn] == nil {
			out[arn] = make(map[string]bool)
		}
		out[arn][svc] = true
	}
	return out, nil
}

// serviceFromEventSource extracts the service prefix from a CloudTrail
// eventSource such as "s3.amazonaws.com" → "s3".
func serviceFromEventSource(src string) string {
	if i := strings.Index(src, "."); i > 0 {
		return strings.ToLower(src[:i])
	}
	return strings.ToLower(src)
}

// normalizeARN converts an assumed-role session ARN to the canonical role ARN
// so CloudTrail activity can be matched against IAM inventory entries.
// arn:aws:sts::ACCT:assumed-role/ROLE/SESSION → arn:aws:iam::ACCT:role/ROLE
func normalizeARN(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return arn
	}
	// arn:aws:sts::ACCT:assumed-role/ROLE/SESSION — six colon-delimited fields
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return arn
	}
	segments := strings.SplitN(parts[5], "/", 3)
	if len(segments) < 2 {
		return arn
	}
	return "arn:aws:iam::" + parts[4] + ":role/" + segments[1]
}
