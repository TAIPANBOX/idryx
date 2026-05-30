package detectors

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func agentGraph() *graph.Store {
	g := graph.New(nil)
	// admin role at the top of two delegation chains
	g.AddIdentity(model.Identity{
		ID: "role:admin", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Owner: "platform", Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	// non-admin role
	g.AddIdentity(model.Identity{
		ID: "role:reader", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Owner: "data", Permissions: []model.Permission{{Name: "ReadOnly"}},
	})
	// agent one hop from admin -> high
	g.AddIdentity(model.Identity{
		ID: "agent:direct", Type: model.IdentityAgent, Source: "agents",
		OnBehalfOf: "role:admin", Owner: "x",
	})
	// agent two hops from admin via a sub-agent -> critical
	g.AddIdentity(model.Identity{
		ID: "agent:sub", Type: model.IdentityAgent, Source: "agents",
		OnBehalfOf: "role:admin", Owner: "x",
	})
	g.AddIdentity(model.Identity{
		ID: "agent:deep", Type: model.IdentityAgent, Source: "agents",
		OnBehalfOf: "agent:sub", Owner: "x",
	})
	// agent that only reaches a reader -> no alert
	g.AddIdentity(model.Identity{
		ID: "agent:safe", Type: model.IdentityAgent, Source: "agents",
		OnBehalfOf: "role:reader", Owner: "x",
	})
	return g
}

func TestExcessiveAgency(t *testing.T) {
	withFixedNow(t)
	got := detect(NewExcessiveAgency(), agentGraph())

	if a, ok := got["agent:direct"]; !ok {
		t.Error("agent:direct should reach admin")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("agent:direct severity = %v, want high", a.Severity)
	}

	if a, ok := got["agent:deep"]; !ok {
		t.Error("agent:deep should reach admin transitively")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("agent:deep severity = %v, want critical (deep chain)", a.Severity)
	}

	if _, ok := got["agent:safe"]; ok {
		t.Error("agent:safe reaches only a reader; should not alert")
	}
	if _, ok := got["role:admin"]; ok {
		t.Error("non-agent identities must not be flagged by excessive_agency")
	}
}

func TestDelegationChainAndEffectivePerms(t *testing.T) {
	g := agentGraph()
	chain := g.DelegationChain("agent:deep")
	want := []string{"agent:deep", "agent:sub", "role:admin"}
	if len(chain) != len(want) {
		t.Fatalf("chain = %v, want %v", chain, want)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, chain[i], want[i])
		}
	}
	perms := g.EffectivePermissions("agent:deep")
	admin := false
	for _, p := range perms {
		if p.Admin {
			admin = true
		}
	}
	if !admin {
		t.Error("agent:deep effective permissions should include admin")
	}
}
