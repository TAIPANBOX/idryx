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
