package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func testServer() *Server {
	g := graph.New(map[string]bool{"alice@x.com": true})
	g.AddEvent(model.Event{Time: time.Now(), IdentityID: "alice@x.com", Type: model.EventLogin, Outcome: "SUCCESS"})
	g.AddEvent(model.Event{Time: time.Now(), IdentityID: "bob@x.com", Type: model.EventLogin, Outcome: "SUCCESS"})
	alerts := []model.Alert{
		{Detector: "impossible_travel", IdentityID: "alice@x.com", Severity: model.SeverityHigh, Time: time.Now(), Summary: "far"},
		{Detector: "mfa_fatigue", IdentityID: "alice@x.com", Severity: model.SeverityCritical, Time: time.Now(), Summary: "burst"},
	}
	return New(g, alerts)
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAPIAlerts(t *testing.T) {
	rr := get(t, testServer().Handler(), "/api/alerts")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got []apiAlert
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2", len(got))
	}
	// critical must sort before high.
	if got[0].Severity != "critical" {
		t.Errorf("first alert severity = %q, want critical", got[0].Severity)
	}
}

func TestAPIIdentities(t *testing.T) {
	rr := get(t, testServer().Handler(), "/api/identities")
	var got []apiIdentity
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d identities, want 2", len(got))
	}
	byID := map[string]apiIdentity{}
	for _, i := range got {
		byID[i.ID] = i
	}
	if !byID["alice@x.com"].Privileged {
		t.Error("alice should be privileged")
	}
	if byID["alice@x.com"].Alerts != 2 {
		t.Errorf("alice alerts = %d, want 2", byID["alice@x.com"].Alerts)
	}
	if byID["bob@x.com"].Alerts != 0 {
		t.Errorf("bob alerts = %d, want 0", byID["bob@x.com"].Alerts)
	}
}

func TestAPIRemediations(t *testing.T) {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::1:role/r",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "AdministratorAccess", Admin: true, Used: false},
			{Name: "S3ReadOnly", Used: true},
		},
	})
	rr := get(t, New(g, nil).Handler(), "/api/remediations")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got []apiRecommendation
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one recommendation, got none")
	}
	if got[0].Kind != "right_size" {
		t.Errorf("kind = %q, want right_size", got[0].Kind)
	}
	if got[0].Identity != "arn:aws:iam::1:role/r" {
		t.Errorf("identity = %q", got[0].Identity)
	}
}

func TestDashboardServed(t *testing.T) {
	rr := get(t, testServer().Handler(), "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "idryx") {
		t.Error("dashboard body missing title")
	}
}

func TestUnknownPath404(t *testing.T) {
	rr := get(t, testServer().Handler(), "/nope")
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	rr := get(t, testServer().Handler(), "/healthz")
	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Errorf("healthz = %d %q", rr.Code, rr.Body.String())
	}
}
