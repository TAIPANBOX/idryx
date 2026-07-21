package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Webhook posts alerts as a JSON array to a generic endpoint (SIEM, SOAR).
// The payload is stable and machine-readable, unlike the Slack sink's text.
type Webhook struct {
	url     string
	min     model.Severity
	headers map[string]string
	client  *http.Client
}

// NewWebhook returns a webhook sink that sends alerts at or above min severity.
//
// headers may be nil. It exists because almost every real destination for
// these alerts wants a credential: a SIEM ingest endpoint, a SOAR intake, or
// TokenFuse Cloud's /v1/findings, which is admin-gated precisely because it
// records an incident rather than raw evidence. Without this the sink could
// only ever talk to something that accepts anonymous writes, which is not a
// system anyone should be sending security findings to.
//
// Headers are outbound only and set by the operator on the command line; this
// changes nothing about what idryx reads or how it detects.
func NewWebhook(url string, min model.Severity, headers map[string]string) *Webhook {
	return &Webhook{
		url:     url,
		min:     min,
		headers: headers,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *Webhook) Name() string { return "webhook" }

type webhookAlert struct {
	Detector string `json:"detector"`
	Identity string `json:"identity"`
	Severity string `json:"severity"`
	Time     string `json:"time"`
	Summary  string `json:"summary"`
}

func (w *Webhook) Send(alerts []model.Alert) error {
	alerts = AtLeast(alerts, w.min)
	if len(alerts) == 0 {
		return nil
	}

	payload := make([]webhookAlert, 0, len(alerts))
	for _, a := range alerts {
		payload = append(payload, webhookAlert{
			Detector: a.Detector,
			Identity: a.IdentityID,
			Severity: a.Severity.String(),
			Time:     a.Time.UTC().Format(time.RFC3339),
			Summary:  a.Summary,
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
