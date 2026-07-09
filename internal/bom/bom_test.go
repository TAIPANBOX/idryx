package bom

import (
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func fixedNow() time.Time { return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) }

func withFixedNow(t *testing.T) {
	t.Helper()
	old := now
	now = fixedNow
	t.Cleanup(func() { now = old })
}

// bomGraph is the synthetic graph the table tests below assert against:
//   - agent:alpha is fully described and admin-capable, and delegates one hop
//     to a principal the graph never ingested as its own node (a dangling
//     OnBehalfOf link -- WalkDelegationChain must stop there, not panic).
//   - agent:beta is a bare agent: no owner/runtime/attestation/tools/chain.
//   - agent:gamma delegates to agent:alpha, so its resolved chain must extend
//     through alpha's own OnBehalfOf too (multi-hop reconstruction stitched
//     across two nodes, agent-passport SPEC Sec5's inventory-source case),
//     and its blast radius must include what it reaches through that chain.
//   - role:sa is a privileged, admin-holding non-agent NHI, and alice is a
//     plain human login: both must be invisible to Build, which is agent-only.
func bomGraph() *graph.Store {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "agent:alpha", Type: model.IdentityAgent,
		Owner: "team-a", Runtime: "langgraph", Attestation: "spiffe-svid",
		Privileged: true,
		Permissions: []model.Permission{
			{Name: "repo_write", Admin: true, Used: true},
			{Name: "repo_read", Admin: false, Used: true},
		},
		OnBehalfOf: []string{"user:human1"},
	})
	g.AddIdentity(model.Identity{ID: "agent:beta", Type: model.IdentityAgent})
	g.AddIdentity(model.Identity{
		ID:          "agent:gamma",
		Type:        model.IdentityAgent,
		Permissions: []model.Permission{{Name: "deploy"}},
		OnBehalfOf:  []string{"agent:alpha"},
	})
	g.AddIdentity(model.Identity{
		ID: "role:sa", Type: model.IdentityServiceAccount, Privileged: true,
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	g.AddEvent(model.Event{IdentityID: "alice@x.com", Type: model.EventLogin, Outcome: "SUCCESS", Time: fixedNow()})
	return g
}

func TestBuildAgentSet(t *testing.T) {
	withFixedNow(t)
	got := Build(bomGraph())

	ids := make([]string, len(got.Agents))
	for i, a := range got.Agents {
		ids[i] = a.ID
	}
	want := []string{"agent:alpha", "agent:beta", "agent:gamma"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("agent set/order = %v, want %v (role:sa and alice must be excluded)", ids, want)
	}
}

func TestBuildAgentFields(t *testing.T) {
	withFixedNow(t)
	got := Build(bomGraph())
	byID := map[string]AgentBOM{}
	for _, a := range got.Agents {
		byID[a.ID] = a
	}

	alpha := byID["agent:alpha"]
	if alpha.Owner != "team-a" || alpha.Runtime != "langgraph" || alpha.Attestation != "spiffe-svid" || !alpha.Privileged {
		t.Errorf("alpha fields wrong: %+v", alpha)
	}
	wantTools := []ToolRef{
		{Name: "repo_read", Admin: false, Used: true},
		{Name: "repo_write", Admin: true, Used: true},
	}
	if !reflect.DeepEqual(alpha.Tools, wantTools) {
		t.Errorf("alpha tools = %+v, want %+v (sorted by name)", alpha.Tools, wantTools)
	}
	wantChain := []string{"agent:alpha", "user:human1"}
	if !reflect.DeepEqual(alpha.DelegationChain, wantChain) {
		t.Errorf("alpha chain = %v, want %v (walk stops at the dangling link)", alpha.DelegationChain, wantChain)
	}
	wantBlast := []string{"repo_read", "repo_write"}
	if !reflect.DeepEqual(alpha.BlastRadius, wantBlast) {
		t.Errorf("alpha blast radius = %v, want %v", alpha.BlastRadius, wantBlast)
	}

	beta := byID["agent:beta"]
	if beta.Owner != "" || beta.Runtime != "" || beta.Attestation != "" || beta.Privileged {
		t.Errorf("beta should be all-zero except ID: %+v", beta)
	}
	if len(beta.Tools) != 0 {
		t.Errorf("beta should have no tools, got %+v", beta.Tools)
	}
	if !reflect.DeepEqual(beta.DelegationChain, []string{"agent:beta"}) {
		t.Errorf("beta (autonomous) chain = %v, want just itself", beta.DelegationChain)
	}
	if len(beta.BlastRadius) != 0 {
		t.Errorf("beta blast radius = %v, want none", beta.BlastRadius)
	}

	gamma := byID["agent:gamma"]
	wantGammaChain := []string{"agent:gamma", "agent:alpha", "user:human1"}
	if !reflect.DeepEqual(gamma.DelegationChain, wantGammaChain) {
		t.Errorf("gamma chain = %v, want %v (multi-hop through alpha's own OnBehalfOf)", gamma.DelegationChain, wantGammaChain)
	}
	wantGammaBlast := []string{"deploy", "repo_read", "repo_write"}
	if !reflect.DeepEqual(gamma.BlastRadius, wantGammaBlast) {
		t.Errorf("gamma blast radius = %v, want %v (its own grant plus alpha's, reached via the chain)", gamma.BlastRadius, wantGammaBlast)
	}
}

func TestBuildDeterministic(t *testing.T) {
	withFixedNow(t)
	g := bomGraph()
	first := Build(g)
	second := Build(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic Build output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	if !first.GeneratedAt.Equal(fixedNow()) {
		t.Errorf("GeneratedAt = %v, want the injected fixedNow %v", first.GeneratedAt, fixedNow())
	}
}

// fakeReader returns identities in a fixed, deliberately non-alphabetical
// order so TestBuildSortsIndependentOfInputOrder exercises Build's own sort
// rather than piggy-backing on graph.Store's (which already sorts
// Identities() itself, so it alone can't prove Build sorts anything).
type fakeReader []*model.Identity

func (f fakeReader) Identities() []*model.Identity { return f }

func TestBuildSortsIndependentOfInputOrder(t *testing.T) {
	withFixedNow(t)
	r := fakeReader{
		{ID: "agent:zeta", Type: model.IdentityAgent},
		{ID: "agent:alpha", Type: model.IdentityAgent},
		{ID: "agent:mu", Type: model.IdentityAgent},
	}
	got := Build(r)
	ids := make([]string, len(got.Agents))
	for i, a := range got.Agents {
		ids[i] = a.ID
	}
	want := []string{"agent:alpha", "agent:mu", "agent:zeta"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("Build did not sort a non-alphabetical Reader: got %v, want %v", ids, want)
	}
}

func TestBuildEmptyGraph(t *testing.T) {
	withFixedNow(t)
	got := Build(graph.New(nil))
	if len(got.Agents) != 0 {
		t.Errorf("empty graph should produce zero agents, got %d", len(got.Agents))
	}
}
