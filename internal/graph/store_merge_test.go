package graph

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func namesOf(ps []model.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

// TestEffectivePermissionsFollowsTheDelegationChain: an agent reaches what
// every identity it acts through is allowed, in chain order, and a link that
// is not in the graph contributes nothing rather than failing the walk.
func TestEffectivePermissionsFollowsTheDelegationChain(t *testing.T) {
	g := New(nil)
	g.AddIdentity(model.Identity{ID: "agent:bot", Type: model.IdentityAgent, OnBehalfOf: []string{"svc:deployer"},
		Permissions: []model.Permission{{Name: "tool:search"}}})
	g.AddIdentity(model.Identity{ID: "svc:deployer", Type: model.IdentityServiceAccount, OnBehalfOf: []string{"alice@x.com"},
		Permissions: []model.Permission{{Name: "s3:write"}}})
	g.AddIdentity(model.Identity{ID: "alice@x.com", OnBehalfOf: []string{"ghost@x.com"}, Permissions: []model.Permission{{Name: "admin", Admin: true}}})

	got := namesOf(g.EffectivePermissions("agent:bot"))
	want := []string{"tool:search", "s3:write", "admin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EffectivePermissions(agent:bot) = %v, want %v", got, want)
	}
	if got := g.EffectivePermissions("nobody"); len(got) != 0 {
		t.Errorf("an unknown identity reaches %v, want nothing", got)
	}
}

// TestAddIdentityAMinimalRecordNeverErasesWhatIsKnown: a second connector
// that knows less about an identity must not blank what the first one
// recorded, and the flags that are evidence (privileged, shadow) only ever
// accumulate.
func TestAddIdentityAMinimalRecordNeverErasesWhatIsKnown(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	used := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	full := model.Identity{
		ID: "agent:a", Type: model.IdentityAgent, Source: "agents", Owner: "team-x",
		Created: created, LastUsed: used, Privileged: true, Runtime: "bedrock",
		OnBehalfOf: []string{"alice@x.com"}, Parent: "agent:root", Attestation: "spiffe",
		DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}}, Shadow: true,
	}
	g := New(nil)
	g.AddIdentity(full)
	g.AddIdentity(model.Identity{ID: "agent:a", LastUsed: used.Add(-time.Hour)})

	got := g.Identities()[0]
	if got.Type != model.IdentityAgent || got.Source != "agents" || got.Owner != "team-x" ||
		!got.Created.Equal(created) || got.Runtime != "bedrock" || got.Parent != "agent:root" ||
		got.Attestation != "spiffe" {
		t.Errorf("metadata was erased by a minimal record: %+v", got)
	}
	if !got.LastUsed.Equal(used) {
		t.Errorf("LastUsed moved back to %s, want it to stay at the later %s", got.LastUsed, used)
	}
	if !got.Privileged || !got.Shadow {
		t.Errorf("privileged=%v shadow=%v, want both to stay true", got.Privileged, got.Shadow)
	}
	if !reflect.DeepEqual(got.OnBehalfOf, []string{"alice@x.com"}) || len(got.DeclaredModels) != 1 {
		t.Errorf("chain %v / models %v lost", got.OnBehalfOf, got.DeclaredModels)
	}

	// A later observation of use moves LastUsed forward.
	later := used.Add(24 * time.Hour)
	g.AddIdentity(model.Identity{ID: "agent:a", LastUsed: later, Owner: "team-y"})
	got = g.Identities()[0]
	if !got.LastUsed.Equal(later) || got.Owner != "team-y" {
		t.Errorf("LastUsed=%s owner=%s, want %s and team-y", got.LastUsed, got.Owner, later)
	}
}

// TestAddIdentityCopiesSlicesItDoesNotOwn: the graph must not alias the
// caller's slices, or a connector reusing its buffer would rewrite the graph.
func TestAddIdentityCopiesSlicesItDoesNotOwn(t *testing.T) {
	chain := []string{"alice@x.com"}
	models := []model.DeclaredModel{{Provider: "openai"}}
	g := New(nil)
	g.AddIdentity(model.Identity{ID: "agent:a", Type: model.IdentityAgent, OnBehalfOf: chain, DeclaredModels: models})
	chain[0] = "mallory@x.com"
	models[0].Provider = "evil"
	got := g.Identities()[0]
	if got.OnBehalfOf[0] != "alice@x.com" || got.DeclaredModels[0].Provider != "openai" {
		t.Errorf("graph aliased the caller's slices: chain=%v models=%v", got.OnBehalfOf, got.DeclaredModels)
	}
}

// TestMarkPrivilegedIgnoresFalseAndEmpty: an empty set changes nothing, a
// false entry is not a mark, and the set still reaches identities created
// after it was applied.
func TestMarkPrivilegedIgnoresFalseAndEmpty(t *testing.T) {
	g := &Store{identities: map[string]*model.Identity{}, seenEvents: map[model.Event]bool{}}
	g.AddIdentity(model.Identity{ID: "bob@x.com"})
	g.MarkPrivileged(nil)
	g.MarkPrivileged(map[string]bool{})
	if g.privileged != nil {
		t.Errorf("an empty set allocated a privileged set: %v", g.privileged)
	}
	g.MarkPrivileged(map[string]bool{"bob@x.com": false, "carol@x.com": true})
	byID := map[string]*model.Identity{}
	for _, id := range g.Identities() {
		byID[id.ID] = id
	}
	if byID["bob@x.com"].Privileged {
		t.Error("a false entry marked bob privileged")
	}
	if _, ok := byID["carol@x.com"]; ok {
		t.Error("MarkPrivileged invented carol, who is not in the graph")
	}
	g.AddEvent(model.Event{IdentityID: "carol@x.com", Type: model.EventLogin})
	for _, id := range g.Identities() {
		if id.ID == "carol@x.com" && !id.Privileged {
			t.Error("carol, created after the set was applied, is not privileged")
		}
	}
}

// TestOpenPgReportsADatabaseThatDoesNotAnswer: the DSN is verified when the
// store opens, so a wrong address is an error at once, named as a ping.
func TestOpenPgReportsADatabaseThatDoesNotAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := OpenPg(ctx, "postgres://idryx@127.0.0.1:1/idryx?sslmode=disable&connect_timeout=2")
	if err == nil {
		_ = s.Close()
		t.Fatal("OpenPg succeeded against a port nothing listens on")
	}
	if s != nil {
		t.Errorf("a failed open returned a store: %v", s)
	}
	if !strings.Contains(err.Error(), "ping postgres") {
		t.Errorf("error = %v, want it named as a failed ping", err)
	}
}
