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

	ids, _, err := Agents(data)
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
	if triage.Runtime != "langgraph" || len(triage.OnBehalfOf) != 1 || triage.OnBehalfOf[0] != "arn:aws:iam::1:role/support" {
		t.Errorf("triage runtime/obo = %q/%v", triage.Runtime, triage.OnBehalfOf)
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

// TestAgentsMalformedCreatedIsCounted is the regression test for the same
// defect class as the four event connectors, applied to a single field
// rather than a whole record: a "created" value that fails to parse as
// RFC3339 was silently absorbed by `if t, err := time.Parse(...); err ==
// nil { id.Created = t }`, leaving Created zero exactly as if the field had
// never been supplied. That zero value is not inert: GenerateRotation
// treats a zero Created as "nothing to rotate" (nil) and stale_nhi skips the
// identity entirely, so a typo in an agent inventory's "created" field
// silently removes that agent from two checks. The agent itself must still
// be ingested (this is a field-level defect, not a dropped record); the
// malformed field must be counted.
func TestAgentsMalformedCreatedIsCounted(t *testing.T) {
	data := []byte(`{
	  "agents": [
	    {"id":"agent:good","runtime":"langgraph","owner":"support-team",
	     "created":"2026-01-01T00:00:00Z","tools":["jira_read"]},
	    {"id":"agent:typo","runtime":"langgraph","owner":"support-team",
	     "created":"2026-01-01","tools":["jira_read"]}
	  ]
	}`)

	ids, rep, err := Agents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d agents, want 2 (both ingested; this is a field defect, not a dropped record)", len(ids))
	}
	if rep.Records != 2 {
		t.Errorf("rep.Records = %d, want 2", rep.Records)
	}
	if rep.Malformed != 1 {
		t.Errorf("rep.Malformed = %d, want 1 (agent:typo's unparseable created)", rep.Malformed)
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}
	if byID["agent:good"].Created.IsZero() {
		t.Error("agent:good has a valid created timestamp; must not be zero")
	}
	if !byID["agent:typo"].Created.IsZero() {
		t.Error("agent:typo's created does not parse; Created should stay zero (unchanged contract), but now it is counted")
	}
}
