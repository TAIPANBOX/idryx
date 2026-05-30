package sink

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func sampleAlerts() []model.Alert {
	t := time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC)
	return []model.Alert{
		{Detector: "impossible_travel", IdentityID: "a@x.com", Severity: model.SeverityHigh, Time: t, Summary: "far"},
		{Detector: "new_device", IdentityID: "b@x.com", Severity: model.SeverityLow, Time: t, Summary: "minor"},
		{Detector: "mfa_fatigue", IdentityID: "c@x.com", Severity: model.SeverityCritical, Time: t, Summary: "burst"},
	}
}

func TestAtLeast(t *testing.T) {
	got := AtLeast(sampleAlerts(), model.SeverityHigh)
	if len(got) != 2 {
		t.Fatalf("got %d alerts >= high, want 2", len(got))
	}
	for _, a := range got {
		if a.Severity < model.SeverityHigh {
			t.Errorf("leaked low-severity alert: %+v", a)
		}
	}
}

func TestWebhookSendsFilteredJSON(t *testing.T) {
	var received []webhookAlert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("bad payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL, model.SeverityHigh).Send(sampleAlerts()); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 {
		t.Fatalf("webhook received %d alerts, want 2", len(received))
	}
	if received[0].Severity != "high" || received[1].Severity != "critical" {
		t.Errorf("unexpected severities: %+v", received)
	}
}

func TestSlackSendsTextAndSkipsEmpty(t *testing.T) {
	var calls int
	var payload slackPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSlack(srv.URL, model.SeverityHigh)
	if err := s.Send(sampleAlerts()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || payload.Text == "" {
		t.Fatalf("expected 1 call with text, got calls=%d text=%q", calls, payload.Text)
	}

	// Nothing at or above critical-only threshold below should still post; but an
	// all-filtered batch must not call the webhook at all.
	calls = 0
	lowOnly := []model.Alert{{Severity: model.SeverityLow, Detector: "x", IdentityID: "y"}}
	if err := NewSlack(srv.URL, model.SeverityHigh).Send(lowOnly); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("expected no call for fully filtered batch, got %d", calls)
	}
}

func TestSinkErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := NewWebhook(srv.URL, model.SeverityNone).Send(sampleAlerts()); err == nil {
		t.Error("expected error on 500 status, got nil")
	}
}
