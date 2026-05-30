// Package remediation generates right-sizing explanations and ready-to-apply
// Terraform snippets to revoke unused permissions and enforce least-privilege.
package remediation

import (
	"fmt"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Recommendation contains the explanation and the copyable Terraform patch/diff.
type Recommendation struct {
	IdentityID  string `json:"identity_id"`
	Explanation string `json:"explanation"`
	Code        string `json:"code"`
}

// Generate evaluates an identity for unused permissions and produces a
// remediation recommendation if applicable. Returns nil if the identity is
// fully right-sized or has no usage metadata.
func Generate(id model.Identity) *Recommendation {
	if len(id.Permissions) == 0 {
		return nil
	}

	// Identify unused permissions
	var unused []model.Permission
	hasUsage := false
	for _, p := range id.Permissions {
		if p.Used {
			hasUsage = true
		} else {
			unused = append(unused, p)
		}
	}

	// If there is no usage data at all, or if everything is used, do not remediate.
	if !hasUsage || len(unused) == 0 {
		return nil
	}

	var code string
	switch id.Source {
	case "aws_iam":
		code = generateAWS(id, unused)
	case "gcp_iam":
		code = generateGCP(id, unused)
	case "azure":
		code = generateAzure(id, unused)
	case "agents":
		code = generateAgent(id, unused)
	default:
		// Generic fallback
		code = generateGeneric(id, unused)
	}

	explanation := fmt.Sprintf(
		"%d of %d granted permissions have never been exercised by this identity. We recommend revoking these unused capabilities to enforce least-privilege.",
		len(unused), len(id.Permissions),
	)

	return &Recommendation{
		IdentityID:  id.ID,
		Explanation: explanation,
		Code:        code,
	}
}

func generateAWS(id model.Identity, unused []model.Permission) string {
	roleName := id.ID
	if i := strings.LastIndex(roleName, "/"); i >= 0 {
		roleName = roleName[i+1:]
	} else if i := strings.LastIndex(roleName, ":"); i >= 0 {
		roleName = roleName[i+1:]
	}

	var sb strings.Builder
	sb.WriteString("# AWS IAM Least-Privilege Remediation\n")
	sb.WriteString("# Revoke unused policy attachments from the IAM role\n\n")

	for i, p := range unused {
		policyARN := p.Name
		if !strings.HasPrefix(policyARN, "arn:") {
			policyARN = fmt.Sprintf("arn:aws:iam::aws:policy/%s", p.Name)
		}
		resName := fmt.Sprintf("revoke_unused_%d", i)

		sb.WriteString(fmt.Sprintf("- resource \"aws_iam_role_policy_attachment\" \"%s\" {\n", resName))
		sb.WriteString(fmt.Sprintf("-   role       = \"%s\"\n", roleName))
		sb.WriteString(fmt.Sprintf("-   policy_arn = \"%s\"\n", policyARN))
		sb.WriteString("- }\n\n")
	}
	return strings.TrimSpace(sb.String())
}

func generateGCP(id model.Identity, unused []model.Permission) string {
	saName := id.ID
	if i := strings.Index(saName, "@"); i >= 0 {
		saName = saName[:i]
	}

	var sb strings.Builder
	sb.WriteString("# GCP IAM Least-Privilege Remediation\n")
	sb.WriteString("# Remove unused role bindings from the Service Account\n\n")

	for i, p := range unused {
		role := p.Name
		if !strings.HasPrefix(role, "roles/") {
			role = fmt.Sprintf("roles/%s", strings.ToLower(role))
		}
		resName := fmt.Sprintf("revoke_unused_%d", i)

		sb.WriteString(fmt.Sprintf("- resource \"google_project_iam_member\" \"%s\" {\n", resName))
		sb.WriteString("-   project = \"my-gcp-project\"\n")
		sb.WriteString(fmt.Sprintf("-   role    = \"%s\"\n", role))
		sb.WriteString(fmt.Sprintf("-   member  = \"serviceAccount:%s\"\n", id.ID))
		sb.WriteString("- }\n\n")
	}
	return strings.TrimSpace(sb.String())
}

func generateAzure(id model.Identity, unused []model.Permission) string {
	spName := id.ID
	if i := strings.Index(spName, "@"); i >= 0 {
		spName = spName[:i]
	}

	var sb strings.Builder
	sb.WriteString("# Azure RBAC Least-Privilege Remediation\n")
	sb.WriteString("# Revoke unused role assignments from the Service Principal\n\n")

	for i, p := range unused {
		resName := fmt.Sprintf("revoke_unused_%d", i)
		sb.WriteString(fmt.Sprintf("- resource \"azurerm_role_assignment\" \"%s\" {\n", resName))
		sb.WriteString("-   scope                = \"/subscriptions/00000000-0000-0000-0000-000000000000\"\n")
		sb.WriteString(fmt.Sprintf("-   role_definition_name = \"%s\"\n", p.Name))
		sb.WriteString(fmt.Sprintf("-   principal_id         = \"%s-object-id\"\n", spName))
		sb.WriteString("- }\n\n")
	}
	return strings.TrimSpace(sb.String())
}

func generateAgent(id model.Identity, unused []model.Permission) string {
	var sb strings.Builder
	sb.WriteString("# AI Agent MCP Configuration Remediation\n")
	sb.WriteString("# Revoke unused tools from the agent's tool declaration list\n\n")
	sb.WriteString("  tools:\n")

	unusedMap := map[string]bool{}
	for _, p := range unused {
		unusedMap[p.Name] = true
	}

	// List active/used tools first (simulated remaining ones)
	for _, p := range id.Permissions {
		if p.Used {
			sb.WriteString(fmt.Sprintf("    - \"%s\"\n", p.Name))
		}
	}

	// Show deleted/unused tools as deleted lines
	for _, p := range unused {
		sb.WriteString(fmt.Sprintf("-   - \"%s\"\n", p.Name))
	}
	return strings.TrimSpace(sb.String())
}

func generateGeneric(id model.Identity, unused []model.Permission) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Generic Remediation for %s (%s)\n", id.ID, id.Source))
	sb.WriteString("# Revoke the following unused capabilities:\n\n")
	for _, p := range unused {
		sb.WriteString(fmt.Sprintf("- %s\n", p.Name))
	}
	return strings.TrimSpace(sb.String())
}
