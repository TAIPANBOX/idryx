package graph

import (
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
