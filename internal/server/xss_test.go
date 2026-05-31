package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// hostileID embeds the classic break-out payload for an onclick="f('<id>')"
// context: a single quote to close the JS string, then script. Identity IDs are
// taken verbatim from ingested inventory/IAM data, so this is attacker-reachable.
const hostileID = "agent:x');document.title='pwned';//"

func hostileServer() *Server {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{ID: hostileID, Type: model.IdentityAgent, Source: "agents"})
	g.AddEvent(model.Event{IdentityID: hostileID, Type: model.EventLogin, Outcome: "SUCCESS"})
	alerts := []model.Alert{{Detector: "shadow_ai", IdentityID: hostileID, Severity: model.SeverityHigh, Summary: "x"}}
	return New(g, alerts)
}

// TestDashboardHTMLDoesNotEmbedIdentityData proves the dashboard is rendered
// client-side: the served HTML must not contain ingested identity IDs at all, so
// no server-side template injection is possible and escaping is governed by the
// client-side esc/escJS helpers.
func TestDashboardHTMLDoesNotEmbedIdentityData(t *testing.T) {
	rr := httptest.NewRecorder()
	hostileServer().Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "document.title='pwned'") {
		t.Error("served dashboard HTML must not embed ingested identity IDs (would be server-side XSS)")
	}
	// The escaper that defends the onclick contexts must be present in the page.
	if !strings.Contains(rr.Body.String(), "function escJS") {
		t.Error("dashboard is missing the escJS helper that defends onclick JS-string contexts")
	}
}

// TestAPIEncodesHostileIDSafely confirms the JSON the dashboard fetches encodes a
// quote-bearing identity ID as data, never as breakable markup. encoding/json
// guarantees this; the test is a regression guard against switching to a
// hand-rolled encoder.
func TestAPIEncodesHostileIDSafely(t *testing.T) {
	for _, path := range []string{"/api/identities", "/api/alerts"} {
		rr := httptest.NewRecorder()
		hostileServer().Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rr.Code)
		}
		// Body must be valid JSON (so the quote is encoded, not literal markup)...
		var v any
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
			t.Errorf("%s did not return valid JSON: %v", path, err)
		}
		// ...and must round-trip the exact hostile ID as a value.
		if !strings.Contains(rr.Body.String(), `agent:x');document.title=`) {
			t.Errorf("%s should carry the hostile ID as JSON data", path)
		}
	}
}
