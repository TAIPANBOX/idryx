//go:build integration

package graph

import (
	"context"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/remediation"
)

func TestSaveAndLoadRemediations(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	recs := []*remediation.Recommendation{
		{IdentityID: "arn:role/etl", Kind: "right_size", Explanation: "2 unused", Code: "- policy a"},
		{IdentityID: "arn:role/etl", Kind: "rotation", Explanation: "old key", Code: "rotate"},
		{IdentityID: "gcp:sa@p.iam", Kind: "right_size", Explanation: "1 unused", Code: "- role b"},
	}
	if err := s.SaveRemediations(ctx, recs); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.Remediations(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d remediations, want 3", len(got))
	}
	// Ordered by identity then kind: arn/right_size, arn/rotation, gcp/right_size.
	if got[0].IdentityID != "arn:role/etl" || got[0].Kind != "right_size" {
		t.Errorf("first = %+v", got[0])
	}

	// Re-saving the same key updates in place, not duplicates.
	recs[0].Explanation = "now 3 unused"
	if err := s.SaveRemediations(ctx, recs[:1]); err != nil {
		t.Fatal(err)
	}
	got, err = s.Remediations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("after re-save got %d, want 3 (no duplicates)", len(got))
	}
	for _, r := range got {
		if r.IdentityID == "arn:role/etl" && r.Kind == "right_size" && r.Explanation != "now 3 unused" {
			t.Errorf("upsert did not refresh explanation: %q", r.Explanation)
		}
	}
}

func TestSaveRemediationsEmpty(t *testing.T) {
	s := testDB(t)
	if err := s.SaveRemediations(context.Background(), nil); err != nil {
		t.Errorf("empty save should be a no-op, got %v", err)
	}
}
