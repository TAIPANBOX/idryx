//go:build integration

// These tests require a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/idryx_test?sslmode=disable \
//	    go test -tags integration ./internal/graph/
package graph

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func testDB(t *testing.T) *PgStore {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	s, err := OpenPg(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Clean slate for a deterministic test.
	if _, err := s.db.Exec(`TRUNCATE events, identities RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPgIngestAndSnapshot(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 30, 9, 0, 0, 0, time.UTC)
	events := []model.Event{
		{IdentityID: "alice@x.com", Time: base, Type: model.EventLogin, Outcome: "SUCCESS", Country: "Ukraine", Device: "Chrome"},
		{IdentityID: "alice@x.com", Time: base.Add(-time.Hour), Type: model.EventLogin, Outcome: "SUCCESS", Country: "Ukraine", Device: "Chrome"},
		{IdentityID: "bob@x.com", Time: base, Type: model.EventMFAChallenge, Outcome: "DENY"},
	}
	if err := s.Ingest(ctx, events, map[string]bool{"alice@x.com": true}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	ids := store.Identities()
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}

	byID := map[string]*model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}
	alice := byID["alice@x.com"]
	if alice == nil || !alice.Privileged {
		t.Fatal("alice missing or not privileged")
	}
	if len(alice.Events) != 2 {
		t.Fatalf("alice events = %d, want 2", len(alice.Events))
	}
	// Snapshot must return events chronologically: earlier one first.
	if !alice.Events[0].Time.Before(alice.Events[1].Time) {
		t.Error("alice events not in chronological order")
	}
}

func TestPgIngestIdempotentPrivilege(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	e := []model.Event{{IdentityID: "carol@x.com", Time: time.Now(), Type: model.EventLogin, Outcome: "SUCCESS"}}

	// First ingest non-privileged, then privileged: the flag must stick to true.
	if err := s.Ingest(ctx, e, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, e, map[string]bool{"carol@x.com": true}); err != nil {
		t.Fatal(err)
	}
	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range store.Identities() {
		if id.ID == "carol@x.com" && !id.Privileged {
			t.Error("privilege flag did not persist as true")
		}
	}
}
