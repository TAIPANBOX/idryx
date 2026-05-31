package remediation

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestGenerateAWS(t *testing.T) {
	id := model.Identity{
		ID:     "arn:aws:iam::123456789012:role/data-pipeline",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "AdministratorAccess", Admin: true, Used: false},
			{Name: "S3ReadOnly", Admin: false, Used: true},
		},
	}

	rem := Generate(id)
	if rem == nil {
		t.Fatal("expected recommendation, got nil")
	}

	if !strings.Contains(rem.Explanation, "1 of 2 granted permissions") {
		t.Errorf("unexpected explanation: %q", rem.Explanation)
	}

	if !strings.Contains(rem.Code, "aws_iam_role_policy_attachment") {
		t.Errorf("expected aws_iam_role_policy_attachment in Terraform code: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "role       = \"data-pipeline\"") {
		t.Errorf("expected role name: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "arn:aws:iam::aws:policy/AdministratorAccess") {
		t.Errorf("expected policy ARN: %q", rem.Code)
	}
}

func TestGenerateGCP(t *testing.T) {
	id := model.Identity{
		ID:     "data-pipeline-sa@my-gcp-project.iam.gserviceaccount.com",
		Type:   model.IdentityServiceAccount,
		Source: "gcp_iam",
		Permissions: []model.Permission{
			{Name: "owner", Admin: true, Used: false},
			{Name: "storage.objectViewer", Admin: false, Used: true},
		},
	}

	rem := Generate(id)
	if rem == nil {
		t.Fatal("expected recommendation, got nil")
	}

	if !strings.Contains(rem.Code, "google_project_iam_member") {
		t.Errorf("expected google_project_iam_member in Terraform: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "roles/owner") {
		t.Errorf("expected roles/owner: %q", rem.Code)
	}
}

func TestGenerateAzure(t *testing.T) {
	id := model.Identity{
		ID:     "data-pipeline-sp@azure.com",
		Type:   model.IdentityServiceAccount,
		Source: "azure",
		Permissions: []model.Permission{
			{Name: "Owner", Admin: true, Used: false},
			{Name: "Reader", Admin: false, Used: true},
		},
	}

	rem := Generate(id)
	if rem == nil {
		t.Fatal("expected recommendation, got nil")
	}

	if !strings.Contains(rem.Code, "azurerm_role_assignment") {
		t.Errorf("expected azurerm_role_assignment in Terraform: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "role_definition_name = \"Owner\"") {
		t.Errorf("expected Owner role: %q", rem.Code)
	}
}

func TestGenerateAgent(t *testing.T) {
	id := model.Identity{
		ID:     "agent:support-triage",
		Type:   model.IdentityAgent,
		Source: "agents",
		Permissions: []model.Permission{
			{Name: "jira_read", Admin: false, Used: true},
			{Name: "s3_delete", Admin: true, Used: false},
		},
	}

	rem := Generate(id)
	if rem == nil {
		t.Fatal("expected recommendation, got nil")
	}

	if !strings.Contains(rem.Code, "tools:") {
		t.Errorf("expected tools section: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "-   - \"s3_delete\"") {
		t.Errorf("expected s3_delete to be flagged as removed: %q", rem.Code)
	}

	if !strings.Contains(rem.Code, "    - \"jira_read\"") {
		t.Errorf("expected jira_read to be preserved: %q", rem.Code)
	}
}

func withFixedNow(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func TestGenerateRotationAWSUser(t *testing.T) {
	at := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	withFixedNow(t, at)
	id := model.Identity{
		ID:      "arn:aws:iam::123456789012:user/ci-bot",
		Type:    model.IdentityServiceAccount,
		Source:  "aws_iam",
		Created: at.Add(-200 * 24 * time.Hour),
	}
	rem := GenerateRotation(id)
	if rem == nil {
		t.Fatal("expected rotation recommendation, got nil")
	}
	if rem.Kind != "rotation" {
		t.Errorf("kind = %q, want rotation", rem.Kind)
	}
	if !strings.Contains(rem.Code, "aws_iam_access_key") || !strings.Contains(rem.Code, "user = \"ci-bot\"") {
		t.Errorf("unexpected code: %q", rem.Code)
	}
	if !strings.Contains(rem.Explanation, "200 days old") {
		t.Errorf("unexpected explanation: %q", rem.Explanation)
	}
}

func TestGenerateRotationSkips(t *testing.T) {
	at := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	withFixedNow(t, at)
	old := at.Add(-200 * 24 * time.Hour)

	// AWS role: short-lived STS creds, nothing to rotate.
	role := model.Identity{ID: "arn:aws:iam::1:role/deploy", Type: model.IdentityServiceAccount, Source: "aws_iam", Created: old}
	if rem := GenerateRotation(role); rem != nil {
		t.Errorf("AWS role should not get a rotation rec, got %+v", rem)
	}
	// Fresh AWS user: within threshold.
	fresh := model.Identity{ID: "arn:aws:iam::1:user/new", Type: model.IdentityServiceAccount, Source: "aws_iam", Created: at.Add(-10 * 24 * time.Hour)}
	if rem := GenerateRotation(fresh); rem != nil {
		t.Errorf("fresh user should not get a rotation rec, got %+v", rem)
	}
	// Human: not an NHI.
	human := model.Identity{ID: "alice@x.com", Type: model.IdentityHuman, Source: "okta", Created: old}
	if rem := GenerateRotation(human); rem != nil {
		t.Errorf("human should not get a rotation rec, got %+v", rem)
	}
	// No creation date: cannot age it.
	noDate := model.Identity{ID: "arn:aws:iam::1:user/x", Type: model.IdentityServiceAccount, Source: "aws_iam"}
	if rem := GenerateRotation(noDate); rem != nil {
		t.Errorf("identity without Created should not get a rotation rec, got %+v", rem)
	}
}

func TestGenerateRotationGCPAzure(t *testing.T) {
	at := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	withFixedNow(t, at)
	old := at.Add(-120 * 24 * time.Hour)

	gcp := model.Identity{ID: "gcp:deploy@proj.iam.gserviceaccount.com", Type: model.IdentityServiceAccount, Source: "gcp_iam", Created: old}
	rem := GenerateRotation(gcp)
	if rem == nil || !strings.Contains(rem.Code, "google_service_account_key") {
		t.Errorf("expected GCP SA key rotation, got %+v", rem)
	}
	if !strings.Contains(rem.Code, "service_account_id = \"deploy@proj.iam.gserviceaccount.com\"") {
		t.Errorf("expected SA email in code: %q", rem.Code)
	}

	az := model.Identity{ID: "deploy-sp@azure.com", Type: model.IdentityServiceAccount, Source: "azure", Created: old}
	rem = GenerateRotation(az)
	if rem == nil || !strings.Contains(rem.Code, "azuread_application_password") {
		t.Errorf("expected Azure SP secret rotation, got %+v", rem)
	}
}

func TestGenerateNoRemediation(t *testing.T) {
	// 1. Fully right-sized (everything is used)
	id1 := model.Identity{
		ID:     "user1",
		Type:   model.IdentityHuman,
		Source: "okta",
		Permissions: []model.Permission{
			{Name: "Login", Used: true},
		},
	}
	if rem := Generate(id1); rem != nil {
		t.Errorf("expected nil for fully right-sized identity, got %+v", rem)
	}

	// 2. No permissions configured
	id2 := model.Identity{
		ID:     "user2",
		Type:   model.IdentityHuman,
		Source: "okta",
	}
	if rem := Generate(id2); rem != nil {
		t.Errorf("expected nil for identity without permissions, got %+v", rem)
	}

	// 3. No usage data at all (all are unused, but hasUsage is false)
	id3 := model.Identity{
		ID:     "user3",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "ReadOnly", Used: false},
		},
		Created: time.Now(),
	}
	if rem := Generate(id3); rem != nil {
		t.Errorf("expected nil when no usage signal is available, got %+v", rem)
	}
}

func TestGenerateRotationAgent(t *testing.T) {
	at := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	withFixedNow(t, at)

	agent := model.Identity{
		ID:         "agent:deploy-bot",
		Type:       model.IdentityAgent,
		Source:     "agents",
		OnBehalfOf: "aws:arn:aws:iam::1:role/deploy",
		Created:    at.Add(-200 * 24 * time.Hour),
	}
	rem := GenerateRotation(agent)
	if rem == nil {
		t.Fatal("expected rotation recommendation, got nil")
	}
	if rem.Kind != "rotation" {
		t.Errorf("kind = %q, want rotation", rem.Kind)
	}
	if !strings.Contains(rem.Code, "agent:deploy-bot") || !strings.Contains(rem.Code, "vault_token") {
		t.Errorf("unexpected code: %q", rem.Code)
	}
	if !strings.Contains(rem.Code, "aws:arn:aws:iam::1:role/deploy") {
		t.Errorf("expected delegation note in code: %q", rem.Code)
	}

	// Fresh agent token: within threshold.
	fresh := model.Identity{ID: "agent:new", Type: model.IdentityAgent, Source: "agents", Created: at.Add(-10 * 24 * time.Hour)}
	if rem := GenerateRotation(fresh); rem != nil {
		t.Errorf("fresh agent token should not get a rotation rec, got %+v", rem)
	}
}
