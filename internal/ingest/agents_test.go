package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestAgents(t *testing.T) {
	data := []byte(`{
	  "agents": [
	    {"id":"agent:triage","runtime":"langgraph","onBehalfOf":"arn:aws:iam::1:role/support",
	     "owner":"support-team","tools":["jira_read","slack_post"]},
	    {"id":"agent:ops","runtime":"bedrock","onBehalfOf":"arn:aws:iam::1:role/admin",
	     "owner":"","tools":["shell_exec","s3_delete"]}
	  ]
	}`)

	ids, err := Agents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d agents, want 2", len(ids))
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	triage := byID["agent:triage"]
	if triage.Type != model.IdentityAgent || triage.Source != "agents" {
		t.Errorf("triage type/source = %v/%q", triage.Type, triage.Source)
	}
	if triage.Runtime != "langgraph" || triage.OnBehalfOf != "arn:aws:iam::1:role/support" {
		t.Errorf("triage runtime/obo = %q/%q", triage.Runtime, triage.OnBehalfOf)
	}
	if triage.HasAdmin() {
		t.Error("triage tools are low-risk; should not be admin")
	}

	ops := byID["agent:ops"]
	if !ops.HasAdmin() {
		t.Error("ops has shell_exec/s3_delete; should be admin-equivalent")
	}
}

func TestIsHighRiskTool(t *testing.T) {
	cases := map[string]bool{
		"shell_exec": true, "s3_delete": true, "admin_panel": true,
		"write_all": true, "tools/*": true,
		"jira_read": false, "slack_post": false,
	}
	for tool, want := range cases {
		if got := isHighRiskTool(tool); got != want {
			t.Errorf("isHighRiskTool(%q) = %v, want %v", tool, got, want)
		}
	}
}
