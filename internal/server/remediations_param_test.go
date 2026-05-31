package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// TestSetRemediationsOverridesRecompute verifies that a persisted set supplied
// via SetRemediations is served by /api/remediations verbatim (with its stored
// created_at), instead of being recomputed from the (here empty) graph.
func TestSetRemediationsOverridesRecompute(t *testing.T) {
	g := graph.New(nil) // empty graph -> recompute would yield zero recommendations
	srv := New(g, nil)
	created := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	srv.SetRemediations([]graph.StoredRemediation{
		{Recommendation: &remediation.Recommendation{IdentityID: "arn:role/etl", Kind: "right_size", Explanation: "2 unused", Code: "- a"}, CreatedAt: created},
		{Recommendation: &remediation.Recommendation{IdentityID: "arn:role/etl", Kind: "rotation", Explanation: "old key", Code: "rotate"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/remediations", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got []struct {
		Identity  string `json:"identity"`
		Kind      string `json:"kind"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d remediations, want 2 (persisted set, not recompute)", len(got))
	}
	if got[0].Identity != "arn:role/etl" || got[0].Kind != "right_size" {
		t.Errorf("first = %+v", got[0])
	}
	if got[0].CreatedAt != "2026-05-31 12:00:00 UTC" {
		t.Errorf("created_at = %q, want stored timestamp", got[0].CreatedAt)
	}
	// A zero CreatedAt is omitted from the JSON.
	if got[1].CreatedAt != "" {
		t.Errorf("zero CreatedAt should be omitted, got %q", got[1].CreatedAt)
	}
}

// TestRemediationsRecomputeByDefault confirms the default path still recomputes
// from the graph when no persisted set is supplied (empty graph -> empty list).
func TestRemediationsRecomputeByDefault(t *testing.T) {
	srv := New(graph.New(nil), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/remediations", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	var got []any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty graph should recompute to 0 remediations, got %d", len(got))
	}
}
