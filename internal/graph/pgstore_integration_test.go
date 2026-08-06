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

// TestPgEventsSnapshotOrdersEqualTimestampsDeterministically is the
// live-Postgres counterpart to TestEventsSnapshotOrderHasIDTiebreaker: two
// events for the same identity with an identical ts must come back from
// Snapshot in a stable, deterministic order (insertion order, via the id
// tiebreaker), matching what the in-memory Store gives for the same
// sequence of AddEvent calls. Before the id tiebreaker, Postgres gives no
// guaranteed order for the tie, so which event new_device/impossible_travel
// treats as the baseline vs the anomaly could flip between snapshots.
func TestPgEventsSnapshotOrdersEqualTimestampsDeterministically(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	sameTS := time.Date(2026, 5, 30, 9, 0, 0, 0, time.UTC)
	first := model.Event{IdentityID: "erin@x.com", Time: sameTS, Type: model.EventLogin, Outcome: "SUCCESS", Device: "laptop-A"}
	second := model.Event{IdentityID: "erin@x.com", Time: sameTS, Type: model.EventLogin, Outcome: "SUCCESS", Device: "laptop-B"}

	// Insert in a specific order, across two separate Ingest calls (as two
	// separate loads would), so the surrogate id order matches this order.
	if err := s.Ingest(ctx, []model.Event{first}, nil); err != nil {
		t.Fatalf("ingest first: %v", err)
	}
	if err := s.Ingest(ctx, []model.Event{second}, nil); err != nil {
		t.Fatalf("ingest second: %v", err)
	}

	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	ids := store.Identities()
	if len(ids) != 1 || len(ids[0].Events) != 2 {
		t.Fatalf("got %+v, want 1 identity with 2 events", ids)
	}
	if ids[0].Events[0].Device != "laptop-A" || ids[0].Events[1].Device != "laptop-B" {
		t.Fatalf("events with equal ts came back in a non-deterministic order: %+v", ids[0].Events)
	}

	// Repeated snapshots must agree: this is "a" deterministic order, not an
	// accident of one query plan.
	store2, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	ids2 := store2.Identities()
	if ids2[0].Events[0].Device != ids[0].Events[0].Device || ids2[0].Events[1].Device != ids[0].Events[1].Device {
		t.Errorf("repeated snapshots produced different orders for equal-ts events: %+v vs %+v", ids[0].Events, ids2[0].Events)
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

// TestPgIngestDedupesEventsOnReplay is the Postgres-backed counterpart to
// graph.TestAddEventDedupesOnNaturalKey: re-ingesting the same event file
// (e.g. `idryx load --source okta okta.json` run twice) must not double the
// stored event count or inflate threshold detectors like mfa_fatigue. Ingest
// upserts on the natural key (identity, ts, type, and the rest of the
// record) with ON CONFLICT DO NOTHING, mirroring the in-memory Store.
func TestPgIngestDedupesEventsOnReplay(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 30, 9, 0, 0, 0, time.UTC)
	events := []model.Event{
		{IdentityID: "dana@x.com", Time: base, Type: model.EventMFAChallenge, Outcome: "DENY"},
		{IdentityID: "dana@x.com", Time: base.Add(time.Minute), Type: model.EventMFAChallenge, Outcome: "DENY"},
		{IdentityID: "dana@x.com", Time: base.Add(2 * time.Minute), Type: model.EventMFAChallenge, Outcome: "DENY"},
	}

	// Ingest the same file twice, exactly as a re-run of `idryx load` would.
	if err := s.Ingest(ctx, events, nil); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if err := s.Ingest(ctx, events, nil); err != nil {
		t.Fatalf("second ingest (replay): %v", err)
	}

	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	ids := store.Identities()
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	if len(ids[0].Events) != 3 {
		t.Fatalf("got %d events after replaying a 3-event file, want 3 (deduped)", len(ids[0].Events))
	}

	// A genuinely different event (different outcome) for the same
	// identity/time/type is not a duplicate and must still be recorded.
	distinct := events[0]
	distinct.Outcome = "SUCCESS"
	if err := s.Ingest(ctx, []model.Event{distinct}, nil); err != nil {
		t.Fatalf("ingest distinct event: %v", err)
	}
	store, err = s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after distinct event: %v", err)
	}
	if got := len(store.Identities()[0].Events); got != 4 {
		t.Fatalf("got %d events after adding a genuinely distinct event, want 4 (must not over-dedupe)", got)
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
				// Customer-managed policy: real account-scoped ARN, distinct
				// from the aws-managed arn:aws:iam::aws:policy/<name> shape
				// remediation would otherwise reconstruct. Must round-trip
				// through Postgres unchanged (see TestGenerateAWSUsesRealCustomerManagedARN
				// in internal/remediation for why this matters).
				{Name: "AdministratorAccess", ARN: "arn:aws:iam::123456789012:policy/AdministratorAccess", Admin: true, Used: false},
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
	if sa.Permissions[0].ARN != "arn:aws:iam::123456789012:policy/AdministratorAccess" {
		t.Errorf("permission ARN did not round-trip through Postgres: %+v", sa.Permissions[0])
	}
	if sa.Permissions[1].ARN != "" {
		t.Errorf("S3ReadOnly should have no ARN (none was set), got %+v", sa.Permissions[1])
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

// TestPgShadowAndDeclaredModelsRoundTrip is the live-database half of the
// two fields the Postgres backend used to drop on the floor.
//
// model.Identity.Shadow (an MCP server in use but absent from the
// sanctioned registry) and model.Identity.DeclaredModels (the Passport 4.5
// declaration) had no columns, were never written by IngestIdentities and
// never read by Snapshot. Three detectors key on them: shadow_mcp and
// agent_shadow_tool on Shadow, undeclared_llm on DeclaredModels. Over
// --db all three ran against a graph where every Shadow flag was false and
// every agent had zero declared models, and all three returned nothing with
// no warning, which is indistinguishable from a clean estate.
func TestPgShadowAndDeclaredModelsRoundTrip(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	identities := []model.Identity{
		{
			ID:     "mcp:shadow-shell@https://mcp.unknown.dev/shell",
			Type:   model.IdentityMCPServer,
			Source: "mcp",
			Shadow: true,
			Permissions: []model.Permission{
				{Name: "shell_exec", Admin: true},
			},
		},
		{
			ID:     "mcp:github-mcp@https://mcp.internal/github",
			Type:   model.IdentityMCPServer,
			Source: "mcp",
			Owner:  "platform",
			Shadow: false,
			Permissions: []model.Permission{
				{Name: "repo_read"},
			},
		},
		{
			ID:      "agent://acme.example/support/bot",
			Type:    model.IdentityAgent,
			Source:  "agents",
			Owner:   "platform",
			Runtime: "langgraph",
			DeclaredModels: []model.DeclaredModel{
				{Provider: "anthropic", Model: "claude-sonnet-4-5", Endpoint: "api.anthropic.com"},
				{Provider: "openai"},
			},
		},
	}

	if err := s.IngestIdentities(ctx, identities); err != nil {
		t.Fatalf("ingest identities: %v", err)
	}
	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	byID := map[string]*model.Identity{}
	for _, id := range store.Identities() {
		byID[id.ID] = id
	}

	shadow := byID["mcp:shadow-shell@https://mcp.unknown.dev/shell"]
	if shadow == nil || !shadow.Shadow {
		t.Errorf("shadow MCP server came back with Shadow=false: %+v, so shadow_mcp and agent_shadow_tool see a sanctioned server", shadow)
	}
	sanctioned := byID["mcp:github-mcp@https://mcp.internal/github"]
	if sanctioned == nil || sanctioned.Shadow {
		t.Errorf("sanctioned MCP server came back with Shadow=true: %+v", sanctioned)
	}

	agent := byID["agent://acme.example/support/bot"]
	if agent == nil {
		t.Fatal("agent missing from snapshot")
	}
	if len(agent.DeclaredModels) != 2 {
		t.Fatalf("DeclaredModels = %+v, want 2 (undeclared_llm skips an agent that declared nothing, so losing these silences it)", agent.DeclaredModels)
	}
	// Declaration order is the Passport's own and is preserved by position.
	if got := agent.DeclaredModels[0]; got.Provider != "anthropic" || got.Model != "claude-sonnet-4-5" || got.Endpoint != "api.anthropic.com" {
		t.Errorf("DeclaredModels[0] = %+v, want the full anthropic declaration", got)
	}
	if got := agent.DeclaredModels[1]; got.Provider != "openai" || got.Model != "" || got.Endpoint != "" {
		t.Errorf("DeclaredModels[1] = %+v, want a provider-only declaration (the optional fields stay empty)", got)
	}

	// Re-ingesting the same batch must be idempotent: the declaration is
	// replaced in place, not appended to, the same way permissions and the
	// delegation chain already are.
	if err := s.IngestIdentities(ctx, identities); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	store, err = s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot after re-ingest: %v", err)
	}
	for _, id := range store.Identities() {
		if id.ID == "agent://acme.example/support/bot" && len(id.DeclaredModels) != 2 {
			t.Errorf("re-ingest duplicated the declaration: %+v", id.DeclaredModels)
		}
	}
}

// TestPgShadowFlagIsStickyLikePrivileged holds the merge rule: the
// in-memory Store.AddIdentity ORs Shadow in and never clears it (a server
// seen unsanctioned once stays flagged for the run), so the Postgres upsert
// has to do the same. A later inventory that omits the flag must not quietly
// sanction a shadow server.
func TestPgShadowFlagIsStickyLikePrivileged(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	id := "mcp:notes-mcp@https://mcp.unknown.dev/notes"
	if err := s.IngestIdentities(ctx, []model.Identity{
		{ID: id, Type: model.IdentityMCPServer, Source: "mcp", Shadow: true},
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if err := s.IngestIdentities(ctx, []model.Identity{
		{ID: id, Type: model.IdentityMCPServer, Source: "mcp", Shadow: false},
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}

	store, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, got := range store.Identities() {
		if got.ID == id && !got.Shadow {
			t.Error("a second ingest without the flag cleared Shadow; it is a sticky OR, like privileged")
		}
	}
}

// TestPgPermissionActionsRoundTrip is the live-database half of the
// escalation fix. The actions a grant allows (read out of an AWS policy
// document, or derived from a GCP/Azure role definition) are what
// privilege_escalation keys on, so a Postgres-backed graph that dropped
// them would silence the detector again exactly the way the missing shadow
// column silenced shadow_mcp. Order is the policy document's own and is
// preserved by position.
func TestPgPermissionActionsRoundTrip(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	identities := []model.Identity{
		{
			ID:     "arn:aws:iam::123456789012:role/ci-deployer",
			Type:   model.IdentityServiceAccount,
			Source: "aws_iam",
			Permissions: []model.Permission{
				{Name: "deploy-service-roles", Actions: []string{"iam:passrole", "ecs:runtask"}},
				{Name: "ReadOnlyAccess", ARN: "arn:aws:iam::aws:policy/ReadOnlyAccess"},
			},
		},
	}
	if err := s.IngestIdentities(ctx, identities); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	read := func() map[string][]string {
		t.Helper()
		store, err := s.Snapshot(ctx)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		out := map[string][]string{}
		for _, id := range store.Identities() {
			for _, p := range id.Permissions {
				out[p.Name] = p.Actions
			}
		}
		return out
	}

	got := read()
	deploy := got["deploy-service-roles"]
	if len(deploy) != 2 || deploy[0] != "iam:passrole" || deploy[1] != "ecs:runtask" {
		t.Errorf("actions = %v, want [iam:passrole ecs:runtask] in document order", deploy)
	}
	if n := len(got["ReadOnlyAccess"]); n != 0 {
		t.Errorf("a grant with no derived actions came back with %d", n)
	}

	// Re-ingesting with a narrowed policy must replace the action list, not
	// append to it: an operator who removed iam:PassRole yesterday cannot
	// still be told they hold it.
	identities[0].Permissions[0].Actions = []string{"ecs:runtask"}
	if err := s.IngestIdentities(ctx, identities); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	got = read()
	if deploy := got["deploy-service-roles"]; len(deploy) != 1 || deploy[0] != "ecs:runtask" {
		t.Errorf("actions after re-ingest = %v, want [ecs:runtask]: the list is replaced, never grown", deploy)
	}
}
