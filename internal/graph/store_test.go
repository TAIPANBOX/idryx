package graph

import (
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// These tests pin down WalkDelegationChain's documented contract without a
// database: exact order/content of the returned chain, and — critically for a
// security product ingesting attacker-influenceable on_behalf_of arrays from
// external NDJSON — guaranteed termination on cycles, self-references, and
// missing links. Simply completing under the test timeout is the termination
// proof; the assertions pin the shape.

// idx builds an identity index the way the excessive_agency detector does,
// from ID -> chain (nil chain = node exists with no principals).
func idx(chains map[string][]string) map[string]*model.Identity {
	out := make(map[string]*model.Identity, len(chains))
	for id, chain := range chains {
		out[id] = &model.Identity{ID: id, OnBehalfOf: chain}
	}
	return out
}

func assertChain(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestWalkDelegationChainOneHop(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a":   {"principal"},
		"principal": nil,
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"), []string{"agent:a", "principal"})
}

// A flattened multi-entry chain on one identity (the event-source case: the
// full root-first array arrives on a single node). The walk returns the start,
// then the array reversed — immediate principal first, root last.
func TestWalkDelegationChainFlattenedArray(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"user://x/root", "agent://x/mid"}, // root-first per SPEC §5
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"),
		[]string{"agent:a", "agent://x/mid", "user://x/root"})
}

// Cross-node stitching (the inventory-source case: one hop per node, three
// nodes deep).
func TestWalkDelegationChainStitched(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"agent:b"},
		"agent:b": {"agent:c"},
		"agent:c": nil,
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"),
		[]string{"agent:a", "agent:b", "agent:c"})
}

// A two-node cycle A→B→A must terminate and return each principal exactly
// once. Nothing about the input prevents this shape: on_behalf_of arrays come
// from external NDJSON and are attacker-influenceable.
func TestWalkDelegationChainTwoNodeCycle(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"agent:b"},
		"agent:b": {"agent:a"},
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"), []string{"agent:a", "agent:b"})
	// And from the other side of the cycle.
	assertChain(t, WalkDelegationChain(index, "agent:b"), []string{"agent:b", "agent:a"})
}

// A self-referencing identity A→A terminates with just A.
func TestWalkDelegationChainSelfReference(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"agent:a"},
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"), []string{"agent:a"})
}

// A chain entry with no corresponding graph node: the walk terminates cleanly
// and the dangling entry is still included as a principal (it IS part of the
// blast radius even if idryx has no inventory row for it yet).
func TestWalkDelegationChainMissingLink(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"ghost://nowhere"},
	})
	assertChain(t, WalkDelegationChain(index, "agent:a"), []string{"agent:a", "ghost://nowhere"})
}

// A start ID absent from the index entirely still returns itself.
func TestWalkDelegationChainUnknownStart(t *testing.T) {
	assertChain(t, WalkDelegationChain(idx(nil), "agent:unknown"), []string{"agent:unknown"})
}

// A longer cycle reached mid-walk (A→B→C→B) and a flattened array containing
// a back-reference to the walker itself (A→[A, P]) — both must terminate,
// dedupe, and keep the legitimate principals.
func TestWalkDelegationChainCycleVariants(t *testing.T) {
	deep := idx(map[string][]string{
		"agent:a": {"agent:b"},
		"agent:b": {"agent:c"},
		"agent:c": {"agent:b"},
	})
	assertChain(t, WalkDelegationChain(deep, "agent:a"),
		[]string{"agent:a", "agent:b", "agent:c"})

	selfInArray := idx(map[string][]string{
		"agent:a":   {"agent:a", "principal"}, // hostile: walker named as its own root
		"principal": nil,
	})
	assertChain(t, WalkDelegationChain(selfInArray, "agent:a"),
		[]string{"agent:a", "principal"})
}

// Store.DelegationChain is the same walk through the public in-memory Store
// path (AddIdentity → DelegationChain), covering the wrapper and AddIdentity's
// chain-copy behavior — including a cycle assembled across AddIdentity calls.
func TestStoreDelegationChain(t *testing.T) {
	g := New(nil)
	g.AddIdentity(model.Identity{ID: "human@x.com"})
	g.AddIdentity(model.Identity{ID: "role:deploy", Type: model.IdentityServiceAccount, OnBehalfOf: []string{"human@x.com"}})
	g.AddIdentity(model.Identity{ID: "agent:bot", Type: model.IdentityAgent, OnBehalfOf: []string{"role:deploy"}})
	assertChain(t, g.DelegationChain("agent:bot"),
		[]string{"agent:bot", "role:deploy", "human@x.com"})

	// Cycle via the store: two agents naming each other.
	g.AddIdentity(model.Identity{ID: "agent:p", Type: model.IdentityAgent, OnBehalfOf: []string{"agent:q"}})
	g.AddIdentity(model.Identity{ID: "agent:q", Type: model.IdentityAgent, OnBehalfOf: []string{"agent:p"}})
	assertChain(t, g.DelegationChain("agent:p"), []string{"agent:p", "agent:q"})
}

// TestBlastRadiusDedupesByName pins the index-based BlastRadius helper's
// documented contract: permissions are unioned across the whole delegation
// chain, but a name shared by two links in the chain counts once, and the
// nearer (starting) identity's copy of that permission wins.
func TestBlastRadiusDedupesByName(t *testing.T) {
	index := idx(map[string][]string{
		"agent:a": {"agent:b"},
		"agent:b": nil,
	})
	index["agent:a"].Permissions = []model.Permission{{Name: "shared", Admin: false}, {Name: "a-only"}}
	index["agent:b"].Permissions = []model.Permission{{Name: "shared", Admin: true}, {Name: "b-only"}}

	got := BlastRadius(index, "agent:a")
	if len(got) != 3 {
		t.Fatalf("BlastRadius = %+v, want 3 de-duplicated permissions", got)
	}
	byName := map[string]model.Permission{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if _, ok := byName["a-only"]; !ok {
		t.Error("missing a-only")
	}
	if _, ok := byName["b-only"]; !ok {
		t.Error("missing b-only")
	}
	if p, ok := byName["shared"]; !ok || p.Admin {
		t.Errorf("shared = %+v, want the nearer (agent:a) non-admin copy to win", p)
	}
}

// TestBlastRadiusEmptyForUnknownStart mirrors
// TestWalkDelegationChainUnknownStart: a start ID absent from the index has
// no permissions of its own and nothing to union, so BlastRadius is empty,
// not an error.
func TestBlastRadiusEmptyForUnknownStart(t *testing.T) {
	if got := BlastRadius(idx(nil), "agent:unknown"); len(got) != 0 {
		t.Errorf("BlastRadius = %+v, want empty", got)
	}
}

// TestAddEventDedupesOnNaturalKey is the regression test for replay
// inflation: re-running `idryx load --source okta okta.json` twice (or
// stitching the same file into --load more than once) must not double-count
// events. AddEvent must dedupe on the natural key (identity, time, type, and
// the rest of the record), not append unconditionally.
func TestAddEventDedupesOnNaturalKey(t *testing.T) {
	g := New(nil)
	e := model.Event{
		IdentityID: "bob@x.com",
		Time:       time.Date(2026, 5, 30, 9, 0, 0, 0, time.UTC),
		Type:       model.EventMFAChallenge,
		Outcome:    "DENY",
		IP:         "1.2.3.4",
		Device:     "iPhone",
	}
	// Simulate the same source file being loaded three times.
	g.AddEvent(e)
	g.AddEvent(e)
	g.AddEvent(e)

	ids := g.Identities()
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	if len(ids[0].Events) != 1 {
		t.Fatalf("got %d events after re-ingesting the identical event 3x, want 1 (deduped)", len(ids[0].Events))
	}

	// A genuinely different event (different IP) for the same identity/time/type
	// is not a duplicate and must still be recorded.
	distinct := e
	distinct.IP = "5.6.7.8"
	g.AddEvent(distinct)
	if got := len(g.Identities()[0].Events); got != 2 {
		t.Fatalf("got %d events after adding a genuinely distinct event, want 2 (must not over-dedupe)", got)
	}

	// The same distinct event replayed again must still dedupe.
	g.AddEvent(distinct)
	if got := len(g.Identities()[0].Events); got != 2 {
		t.Fatalf("got %d events after replaying the distinct event again, want 2", got)
	}
}

// TestAddIdentityMergesDeclaredModels pins AddIdentity's handling of the
// passport-sourced DeclaredModels field: it must survive into the graph (the
// undeclared_llm detector depends on this, the same way attestation_missing
// depends on Attestation surviving), and a later merge carrying no
// DeclaredModels at all must not clear a value set by an earlier one --
// the same "only overwrite when the incoming value is non-empty" contract
// every other passport-sourced field on Identity already follows.
func TestAddIdentityMergesDeclaredModels(t *testing.T) {
	g := New(nil)
	g.AddIdentity(model.Identity{
		ID:   "agent:etl",
		Type: model.IdentityAgent,
		DeclaredModels: []model.DeclaredModel{
			{Provider: "anthropic", Model: "claude-sonnet-4-5", Endpoint: "api.anthropic.com"},
		},
	})
	ids := g.Identities()
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	want := model.DeclaredModel{Provider: "anthropic", Model: "claude-sonnet-4-5", Endpoint: "api.anthropic.com"}
	if len(ids[0].DeclaredModels) != 1 || ids[0].DeclaredModels[0] != want {
		t.Fatalf("DeclaredModels = %+v, want [%+v]", ids[0].DeclaredModels, want)
	}

	// A second AddIdentity for the same ID with no DeclaredModels (e.g. an
	// egress connector touching the identity after the passport already
	// enriched it) must not wipe the earlier declaration.
	g.AddIdentity(model.Identity{ID: "agent:etl", Type: model.IdentityAgent})
	if got := g.Identities()[0].DeclaredModels; len(got) != 1 || got[0] != want {
		t.Fatalf("DeclaredModels after empty merge = %+v, want unchanged [%+v]", got, want)
	}
}

// permNames returns the permission names on the single identity in g, in
// stored order, so a test can assert both the count and that no name repeats.
func permNames(t *testing.T, g *Store) []string {
	t.Helper()
	ids := g.Identities()
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	out := make([]string, 0, len(ids[0].Permissions))
	for _, p := range ids[0].Permissions {
		out = append(out, p.Name)
	}
	return out
}

// TestAddIdentityDedupesPermissionsByName is the inventory-side half of the
// replay-inflation rule TestAddEventDedupesOnNaturalKey holds for events: the
// same inventory ingested twice (the same file named in --load more than once,
// or two connectors reporting the same identity) must not double an identity's
// permission list. least_privilege reports "N/M granted permissions unused"
// straight to an operator and names each unused grant, so a duplicated
// permission both inflates M and prints the same grant twice in the revoke
// recommendation.
func TestAddIdentityDedupesPermissionsByName(t *testing.T) {
	in := model.Identity{
		ID:   "agent:support-triage",
		Type: model.IdentityAgent,
		Permissions: []model.Permission{
			{Name: "slack_post"},
			{Name: "s3_read", Used: true},
		},
	}

	g := New(nil)
	g.AddIdentity(in)
	g.AddIdentity(in)
	if got := permNames(t, g); len(got) != 2 {
		t.Fatalf("permissions after re-ingesting the identical inventory 2x = %v, want 2 (deduped by name)", got)
	}

	// A genuinely new grant from a later source (e.g. an mcp inventory adding
	// a tool to an identity aws_iam already described) is not a duplicate and
	// must still be recorded: the merge is a union by name, not a replace.
	g.AddIdentity(model.Identity{
		ID:          "agent:support-triage",
		Permissions: []model.Permission{{Name: "s3_delete"}},
	})
	if got := permNames(t, g); len(got) != 3 {
		t.Fatalf("permissions after a later source added one new grant = %v, want 3 (must not over-dedupe)", got)
	}

	// Duplicate names inside a single incoming slice collapse too, the way
	// the Postgres backend's ON CONFLICT (identity_id, name) already makes
	// them collapse within one IngestIdentities batch.
	dupWithin := New(nil)
	dupWithin.AddIdentity(model.Identity{
		ID: "agent:support-triage",
		Permissions: []model.Permission{
			{Name: "slack_post"},
			{Name: "slack_post"},
		},
	})
	if got := permNames(t, dupWithin); len(got) != 1 {
		t.Fatalf("permissions from one slice naming the same grant twice = %v, want 1", got)
	}
}

// TestAddIdentityMergesPermissionFlags pins what happens to the flags when two
// reports of the same grant meet. AddIdentity already merges the identity's own
// fields rather than replacing them, and each permission field follows the rule
// its kind already follows one scope up: booleans are ORed (like Privileged and
// Shadow), and a non-empty string wins while an empty one never clears (like
// Source, Owner, Runtime and Attestation). For a security tool that direction
// is the safe one: an observation that a grant is admin-equivalent, or that it
// was exercised, cannot be erased by a later source that simply did not look.
func TestAddIdentityMergesPermissionFlags(t *testing.T) {
	g := New(nil)
	g.AddIdentity(model.Identity{
		ID:          "role:deploy",
		Permissions: []model.Permission{{Name: "AdministratorAccess"}},
	})
	// A usage-enriched re-ingest of the same role: same grant, now known to be
	// admin-equivalent, observed in use, and carrying its real ARN.
	g.AddIdentity(model.Identity{
		ID: "role:deploy",
		Permissions: []model.Permission{{
			Name:  "AdministratorAccess",
			Admin: true,
			Used:  true,
			ARN:   "arn:aws:iam::aws:policy/AdministratorAccess",
		}},
	})

	ids := g.Identities()
	if len(ids) != 1 || len(ids[0].Permissions) != 1 {
		t.Fatalf("permissions = %+v, want exactly 1", ids[0].Permissions)
	}
	got := ids[0].Permissions[0]
	want := model.Permission{
		Name:  "AdministratorAccess",
		Admin: true,
		Used:  true,
		ARN:   "arn:aws:iam::aws:policy/AdministratorAccess",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged permission = %+v, want %+v", got, want)
	}

	// The reverse order must not undo any of it: a later bare report of the
	// same grant (an inventory source with no usage data and no ARN concept)
	// leaves every flag standing.
	g.AddIdentity(model.Identity{
		ID:          "role:deploy",
		Permissions: []model.Permission{{Name: "AdministratorAccess"}},
	})
	if got := g.Identities()[0].Permissions[0]; !reflect.DeepEqual(got, want) {
		t.Fatalf("permission after a later bare report = %+v, want unchanged %+v", got, want)
	}
}

// TestMarkPrivilegedAppliesToAnAlreadyBuiltGraph is the store-level half of
// the ignored --privileged flag. Over --db the graph is a Snapshot built
// from what the database holds, so the CLI's privileged set has to be folded
// into an existing graph rather than handed to New() before it is filled.
// Ten detectors raise severity for a privileged identity, so a set that is
// accepted and dropped produces systematically under-ranked findings with
// nothing saying why.
func TestMarkPrivilegedAppliesToAnAlreadyBuiltGraph(t *testing.T) {
	s := New(nil) // nil set, as Snapshot builds it when no row is flagged
	s.AddIdentity(model.Identity{ID: "alice@x.com"})
	s.AddIdentity(model.Identity{ID: "bob@x.com"})

	s.MarkPrivileged(map[string]bool{"alice@x.com": true, "never-seen@x.com": true})

	byID := map[string]*model.Identity{}
	for _, id := range s.Identities() {
		byID[id.ID] = id
	}
	if !byID["alice@x.com"].Privileged {
		t.Error("alice was named in the privileged set and came back unprivileged")
	}
	if byID["bob@x.com"].Privileged {
		t.Error("bob was not in the set and was marked privileged")
	}
	if _, ok := byID["never-seen@x.com"]; ok {
		t.Error("an identity named in the set but absent from the graph must not be invented")
	}

	// An identity that arrives later still picks the flag up, the same way
	// New(privileged) has always behaved.
	s.AddEvent(model.Event{IdentityID: "never-seen@x.com"})
	for _, id := range s.Identities() {
		if id.ID == "never-seen@x.com" && !id.Privileged {
			t.Error("an identity created after MarkPrivileged did not pick up the flag")
		}
	}
}

// TestAddIdentityUnionsActionsAcrossReports pins the field the dedup rule
// gained on 2026-08-06, when real IAM policy-document parsing landed beside
// permission dedup. The two changes met here: dedup folds repeated reports of
// one grant, and Actions is the field a blind source reports empty.
//
// privilege_escalation reads Actions to decide whether a grant allows
// iam:PassRole, so a blind report overwriting a sighted one would not just
// lose data, it would silence a detector. Red before unionActions existed:
// the second AddIdentity left Actions empty.
func TestAddIdentityUnionsActionsAcrossReports(t *testing.T) {
	g := New(nil)
	g.AddIdentity(model.Identity{
		ID: "role:ci-deployer",
		Permissions: []model.Permission{{
			Name:    "deploy-service-roles",
			Actions: []string{"iam:passrole"},
		}},
	})
	// A second connector describes the same grant with no document to read,
	// which is what an AWS-managed policy looks like in an export.
	g.AddIdentity(model.Identity{
		ID:          "role:ci-deployer",
		Permissions: []model.Permission{{Name: "deploy-service-roles"}},
	})

	ids := g.Identities()
	if len(ids) != 1 || len(ids[0].Permissions) != 1 {
		t.Fatalf("permissions = %+v, want exactly 1", ids[0].Permissions)
	}
	if got := ids[0].Permissions[0].Actions; !reflect.DeepEqual(got, []string{"iam:passrole"}) {
		t.Fatalf("actions = %v, want [iam:passrole]: a blind report cleared a sighted one", got)
	}

	// Two sighted reports union without repeating.
	g.AddIdentity(model.Identity{
		ID: "role:ci-deployer",
		Permissions: []model.Permission{{
			Name:    "deploy-service-roles",
			Actions: []string{"iam:passrole", "sts:assumerole"},
		}},
	})
	want := []string{"iam:passrole", "sts:assumerole"}
	if got := g.Identities()[0].Permissions[0].Actions; !reflect.DeepEqual(got, want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
}
