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
		{IdentityID: "agent://x/bot", Time: base.Add(2 * time.Hour), Type: model.EventBudgetExhausted, Severity: "critical"},
	}
	if err := s.Ingest(ctx, events, map[string]bool{"alice@x.com": true}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

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
	bot := byID["agent://x/bot"]
	if bot == nil || len(bot.Events) != 1 {
		t.Fatalf("bot missing or wrong event count: %+v", bot)
	}
	if bot.Events[0].Type != model.EventBudgetExhausted || bot.Events[0].Severity != "critical" {
		t.Errorf("tokenfuse event severity not persisted correctly: %+v", bot.Events[0])
	}
	if bot.Events[0].Outcome != "" {
		t.Errorf("tokenfuse event Outcome = %q, want empty", bot.Events[0].Outcome)
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
			OnBehalfOf: []string{"human-owner@x.com"},
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
			OnBehalfOf: []string{"service-account-1"},
			Permissions: []model.Permission{
				{Name: "AgentTool_Jira", Admin: false, Used: true},
			},
		},
		{
			// A tokenfuse-style identity whose own OnBehalfOf array already
			// carries a full, multi-hop chain (root-first) rather than one
			// hop reconstructed via a separate identity row. Exercises the
			// on_behalf_of join table's position ordering end to end.
			ID:         "ai-agent-2",
			Type:       model.IdentityAgent,
			Source:     "tokenfuse",
			Owner:      "human-owner@x.com",
			Runtime:    "tokenfuse-run",
			OnBehalfOf: []string{"human-owner@x.com", "service-account-1"},
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
	if len(ids) != 4 {
		t.Fatalf("got %d identities, want 4", len(ids))
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
	if agent == nil || agent.Type != model.IdentityAgent || agent.Runtime != "langgraph" ||
		len(agent.OnBehalfOf) != 1 || agent.OnBehalfOf[0] != "service-account-1" {
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

	// ai-agent-2 carries its full chain in one array (persisted via the
	// on_behalf_of join table): position order must survive the round trip.
	agent2 := byID["ai-agent-2"]
	if agent2 == nil || len(agent2.OnBehalfOf) != 2 ||
		agent2.OnBehalfOf[0] != "human-owner@x.com" || agent2.OnBehalfOf[1] != "service-account-1" {
		t.Errorf("invalid ai-agent-2 chain: %+v", agent2)
	}
	chain2 := store.DelegationChain("ai-agent-2")
	expectedChain2 := []string{"ai-agent-2", "service-account-1", "human-owner@x.com"}
	if len(chain2) != len(expectedChain2) {
		t.Fatalf("ai-agent-2 chain = %v, want %v", chain2, expectedChain2)
	}
	for i, link := range chain2 {
		if link != expectedChain2[i] {
			t.Errorf("ai-agent-2 chain at %d = %q, want %q", i, link, expectedChain2[i])
		}
	}
}

func sortPermissions(perms []model.Permission) {
	sort.Slice(perms, func(i, j int) bool {
		return perms[i].Name < perms[j].Name
	})
}

// TestPgLegacyOnBehalfOfBackfill covers the destructive-free migration path:
// a database created before Phase 5.1 stored the delegation link as a single
// identities.on_behalf_of column. Re-applying the schema must backfill each
// non-empty legacy value into the on_behalf_of join table as a one-hop chain
// (position 0) BEFORE dropping the old column, and re-running the migration
// afterwards must be a harmless no-op.
func TestPgLegacyOnBehalfOfBackfill(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	// Recreate the pre-Phase-5.1 shape: the single legacy column, plus rows
	// that use it. testDB already applied the current schema, so the column
	// is absent — add it back the way an old install would have it.
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE identities ADD COLUMN on_behalf_of TEXT REFERENCES identities(id) ON DELETE SET NULL`); err != nil {
		t.Fatalf("re-add legacy column: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO identities (id, type) VALUES
		 ('legacy-principal@x.com', ''),
		 ('legacy-agent-1', 'agent'),
		 ('legacy-agent-2', 'agent')`); err != nil {
		t.Fatalf("insert legacy identities: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE identities SET on_behalf_of = 'legacy-principal@x.com' WHERE id = 'legacy-agent-1'`); err != nil {
		t.Fatalf("set legacy on_behalf_of: %v", err)
	}
	// legacy-agent-2 keeps a NULL on_behalf_of: it must NOT gain a chain row.

	// Re-apply the schema: this is exactly what OpenPg does on an old
	// database. The backfill must run before the column is dropped.
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("migrate over legacy shape: %v", err)
	}

	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	byID := map[string]*model.Identity{}
	for _, id := range store.Identities() {
		byID[id.ID] = id
	}

	a1 := byID["legacy-agent-1"]
	if a1 == nil || len(a1.OnBehalfOf) != 1 || a1.OnBehalfOf[0] != "legacy-principal@x.com" {
		t.Errorf("legacy-agent-1 chain = %+v, want [legacy-principal@x.com] backfilled at position 0", a1)
	}
	a2 := byID["legacy-agent-2"]
	if a2 == nil || len(a2.OnBehalfOf) != 0 {
		t.Errorf("legacy-agent-2 chain = %+v, want empty (NULL legacy value must not backfill)", a2)
	}
	chain := store.DelegationChain("legacy-agent-1")
	want := []string{"legacy-agent-1", "legacy-principal@x.com"}
	if len(chain) != len(want) || chain[0] != want[0] || chain[1] != want[1] {
		t.Errorf("legacy-agent-1 delegation chain = %v, want %v", chain, want)
	}

	// Idempotency: the column is gone now, so a further migrate must neither
	// fail nor duplicate/overwrite the chain.
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("re-migrate after backfill: %v", err)
	}
	store, err = s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after re-migrate: %v", err)
	}
	for _, id := range store.Identities() {
		if id.ID == "legacy-agent-1" && (len(id.OnBehalfOf) != 1 || id.OnBehalfOf[0] != "legacy-principal@x.com") {
			t.Errorf("re-migrate changed legacy-agent-1 chain: %v", id.OnBehalfOf)
		}
	}
}
