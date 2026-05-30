//go:build integration

// These tests require a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/idryx_test?sslmode=disable \
//	    go test -tags integration ./internal/graph/
package graph

import (
	"context"
	"os"
	"sort"
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
		{IdentityID: "alice@x.com", Time: base.Add(time.Hour), Type: model.EventEgress, Outcome: "SUCCESS", Resource: "api.openai.com"},
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
	if len(alice.Events) != 3 {
		t.Fatalf("alice events = %d, want 3", len(alice.Events))
	}
	// Snapshot must return events chronologically: earlier one first.
	if !alice.Events[0].Time.Before(alice.Events[1].Time) {
		t.Error("alice events not in chronological order")
	}
	if alice.Events[2].Type != model.EventEgress || alice.Events[2].Resource != "api.openai.com" {
		t.Errorf("egress event resource not persisted correctly: %+v", alice.Events[2])
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

func TestPgIngestIdentitiesAndSnapshot(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	createdTime := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	lastUsedTime := time.Date(2026, 5, 30, 18, 30, 0, 0, time.UTC)

	identities := []model.Identity{
		{
			ID:         "human-owner@x.com",
			Type:       model.IdentityHuman,
			Privileged: true,
		},
		{
			ID:         "service-account-1",
			Type:       model.IdentityServiceAccount,
			Source:     "aws_iam",
			Owner:      "human-owner@x.com",
			Created:    createdTime,
			LastUsed:   lastUsedTime,
			Privileged: false,
			Permissions: []model.Permission{
				{Name: "AdministratorAccess", Admin: true, Used: false},
				{Name: "S3ReadOnly", Admin: false, Used: true},
			},
		},
		{
			ID:         "ai-agent-1",
			Type:       model.IdentityAgent,
			Source:     "agents",
			Owner:      "human-owner@x.com",
			Created:    createdTime.Add(time.Hour),
			LastUsed:   lastUsedTime.Add(time.Hour),
			Privileged: false,
			Runtime:    "langgraph",
			OnBehalfOf: "service-account-1",
			Permissions: []model.Permission{
				{Name: "AgentTool_Jira", Admin: false, Used: true},
			},
		},
	}

	// Load identities
	if err := s.IngestIdentities(ctx, identities); err != nil {
		t.Fatalf("ingest identities: %v", err)
	}

	// Snapshot back
	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	ids := store.Identities()
	if len(ids) != 3 {
		t.Fatalf("got %d identities, want 3", len(ids))
	}

	byID := map[string]*model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	owner := byID["human-owner@x.com"]
	if owner == nil || !owner.Privileged || owner.Type != model.IdentityHuman {
		t.Errorf("invalid owner: %+v", owner)
	}

	sa := byID["service-account-1"]
	if sa == nil || sa.Type != model.IdentityServiceAccount || sa.Source != "aws_iam" || sa.Owner != "human-owner@x.com" {
		t.Errorf("invalid service account: %+v", sa)
	}
	if !sa.Created.Equal(createdTime) || !sa.LastUsed.Equal(lastUsedTime) {
		t.Errorf("invalid sa timestamps: created=%v, lastUsed=%v", sa.Created, sa.LastUsed)
	}
	if len(sa.Permissions) != 2 {
		t.Fatalf("sa permissions count = %d, want 2", len(sa.Permissions))
	}
	// Sort permissions for stable comparison
	sortPermissions(sa.Permissions)
	if sa.Permissions[0].Name != "AdministratorAccess" || !sa.Permissions[0].Admin || sa.Permissions[0].Used {
		t.Errorf("invalid permission 0: %+v", sa.Permissions[0])
	}

	agent := byID["ai-agent-1"]
	if agent == nil || agent.Type != model.IdentityAgent || agent.Runtime != "langgraph" || agent.OnBehalfOf != "service-account-1" {
		t.Errorf("invalid agent: %+v", agent)
	}
	if len(agent.Permissions) != 1 || agent.Permissions[0].Name != "AgentTool_Jira" || !agent.Permissions[0].Used {
		t.Errorf("invalid agent permissions: %+v", agent.Permissions)
	}

	// Verify delegation chain and effective permissions through the snapshot's Store methods
	chain := store.DelegationChain("ai-agent-1")
	expectedChain := []string{"ai-agent-1", "service-account-1", "human-owner@x.com"}
	if len(chain) != 3 {
		t.Fatalf("invalid chain length: %d, want 3", len(chain))
	}
	for i, link := range chain {
		if link != expectedChain[i] {
			t.Errorf("chain at %d = %q, want %q", i, link, expectedChain[i])
		}
	}

	effPerms := store.EffectivePermissions("ai-agent-1")
	if len(effPerms) != 3 { // 2 from sa-1 + 1 from agent-1
		t.Fatalf("effective permissions count = %d, want 3", len(effPerms))
	}
}

func sortPermissions(perms []model.Permission) {
	sort.Slice(perms, func(i, j int) bool {
		return perms[i].Name < perms[j].Name
	})
}
