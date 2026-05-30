package detectors

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func lpGraph() *graph.Store {
	g := graph.New(nil)
	// agent with usage data: 1 of 3 tools used -> recommend revoking 2
	g.AddIdentity(model.Identity{
		ID: "agent:triage", Type: model.IdentityAgent, Source: "agents", Owner: "x",
		Permissions: []model.Permission{
			{Name: "jira_read", Used: true},
			{Name: "slack_post", Used: false},
			{Name: "shell_exec", Admin: true, Used: false},
		},
	})
	// NHI with permissions but no usage data -> must stay silent
	g.AddIdentity(model.Identity{
		ID: "role:etl", Type: model.IdentityServiceAccount, Source: "aws_iam", Owner: "y",
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	// agent fully using its grants -> no recommendation
	g.AddIdentity(model.Identity{
		ID: "agent:tidy", Type: model.IdentityAgent, Source: "agents", Owner: "x",
		Permissions: []model.Permission{{Name: "kb_read", Used: true}},
	})
	return g
}

func TestLeastPrivilege(t *testing.T) {
	withFixedNow(t)
	got := detect(NewLeastPrivilege(), lpGraph())

	a, ok := got["agent:triage"]
	if !ok {
		t.Fatal("agent:triage should have an unused-permission recommendation")
	}
	// An unused admin grant raises severity to high.
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high (unused admin)", a.Severity)
	}
	if !strings.Contains(a.Summary, "shell_exec") || !strings.Contains(a.Summary, "slack_post") {
		t.Errorf("summary should list both unused tools: %q", a.Summary)
	}
	if strings.Contains(a.Summary, "jira_read") {
		t.Errorf("used tool must not be recommended for revocation: %q", a.Summary)
	}

	if _, ok := got["role:etl"]; ok {
		t.Error("identity without usage data must not be flagged")
	}
	if _, ok := got["agent:tidy"]; ok {
		t.Error("fully-used grants must not be flagged")
	}
}
