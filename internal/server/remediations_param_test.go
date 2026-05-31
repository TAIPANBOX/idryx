package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// TestSetRemediationsOverridesRecompute verifies that a persisted set supplied
// via SetRemediations is served by /api/remediations verbatim, instead of being
// recomputed from the (here empty) graph.
func TestSetRemediationsOverridesRecompute(t *testing.T) {
	g := graph.New(nil) // empty graph -> recompute would yield zero recommendations
	srv := New(g, nil)
	srv.SetRemediations([]*remediation.Recommendation{
		{IdentityID: "arn:role/etl", Kind: "right_size", Explanation: "2 unused", Code: "- a"},
		{IdentityID: "arn:role/etl", Kind: "rotation", Explanation: "old key", Code: "rotate"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/remediations", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got []struct {
		Identity string `json:"identity"`
		Kind     string `json:"kind"`
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
