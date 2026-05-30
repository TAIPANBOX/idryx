package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Slack posts alerts to an incoming-webhook URL as a formatted message.
type Slack struct {
	webhookURL string
	min        model.Severity
	client     *http.Client
}

// NewSlack returns a Slack sink that sends alerts at or above min severity.
func NewSlack(webhookURL string, min model.Severity) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		min:        min,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Slack) Name() string { return "slack" }

type slackPayload struct {
	Text string `json:"text"`
}

func (s *Slack) Send(alerts []model.Alert) error {
	alerts = AtLeast(alerts, s.min)
	if len(alerts) == 0 {
		return nil
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*idryx: %d alert(s)*\n", len(alerts))
	for _, a := range alerts {
		fmt.Fprintf(&buf, "• [%s] `%s` %s — %s\n",
			a.Severity, a.Detector, a.IdentityID, a.Summary)
	}

	body, err := json.Marshal(slackPayload{Text: buf.String()})
	if err != nil {
		return err
	}
	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}
