package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// TestIdentitiesRemediationCreatedAt verifies that when the server is given a
// persisted remediation set (serve --db), the per-identity remediation in
// /api/identities carries the stored generation time, and that without a
// persisted set the field is omitted (live recompute has no timestamp).
func TestIdentitiesRemediationCreatedAt(t *testing.T) {
	srv := New(lpGraph(), nil)
	created := time.Date(2026, 5, 31, 9, 30, 0, 0, time.UTC)
	srv.SetRemediations([]graph.StoredRemediation{
		{Recommendation: &remediation.Recommendation{IdentityID: "arn:aws:iam::1:role/etl", Kind: "right_size"}, CreatedAt: created},
	})

	got := fetchIdentity(t, srv, "arn:aws:iam::1:role/etl")
	if got.Remediation == nil {
		t.Fatal("expected a right_size remediation")
	}
	if got.Remediation.CreatedAt != "2026-05-31 09:30:00 UTC" {
		t.Errorf("remediation.created_at = %q, want the persisted time", got.Remediation.CreatedAt)
	}
}

func TestIdentitiesRemediationCreatedAtOmittedWhenLive(t *testing.T) {
	srv := New(lpGraph(), nil) // no SetRemediations -> live recompute, no timestamps

	got := fetchIdentity(t, srv, "arn:aws:iam::1:role/etl")
	if got.Remediation == nil {
		t.Fatal("expected a right_size remediation")
	}
	if got.Remediation.CreatedAt != "" {
		t.Errorf("created_at should be empty for live recompute, got %q", got.Remediation.CreatedAt)
	}
}

// lpGraph builds a graph with one NHI that has an unused permission, so
// remediation.Generate produces a right_size recommendation for it.
func lpGraph() *graph.Store {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::1:role/etl",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Owner:  "data",
		Permissions: []model.Permission{
			{Name: "AmazonS3ReadOnlyAccess", Used: true},
			{Name: "AmazonEC2FullAccess", Used: false},
		},
	})
	return g
}

func fetchIdentity(t *testing.T, srv *Server, id string) apiIdentity {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/identities", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var ids []apiIdentity
	if err := json.Unmarshal(rr.Body.Bytes(), &ids); err != nil {
		t.Fatal(err)
	}
	for _, x := range ids {
		if x.ID == id {
			return x
		}
	}
	t.Fatalf("identity %q not found", id)
	return apiIdentity{}
}
