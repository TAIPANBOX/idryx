package ingest

import (
	"encoding/json"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// gcpInventory is the input idryx reads for the gcp_iam source: a list of
// service accounts (from `gcloud iam service-accounts list`) and the project
// IAM policy (from `gcloud projects get-iam-policy`). Bindings map roles to
// members; idryx attaches roles to the service accounts they name.
type gcpInventory struct {
	ServiceAccounts []gcpServiceAccount `json:"serviceAccounts"`
	Policy          gcpPolicy           `json:"policy"`
}

type gcpServiceAccount struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`
}

type gcpPolicy struct {
	Bindings []gcpBinding `json:"bindings"`
}

type gcpBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// GCPIAM parses the gcp_iam inventory into service-account identities. The
// member prefix "serviceAccount:" links a binding to an account; roles ending
// in owner/admin/editor are treated as admin-equivalent.
func GCPIAM(data []byte) ([]model.Identity, error) {
	var in gcpInventory
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}

	// Index roles granted to each service-account email.
	rolesByEmail := map[string][]string{}
	for _, b := range in.Policy.Bindings {
		for _, m := range b.Members {
			email, ok := strings.CutPrefix(m, "serviceAccount:")
			if !ok {
				continue
			}
			rolesByEmail[email] = append(rolesByEmail[email], b.Role)
		}
	}

	out := make([]model.Identity, 0, len(in.ServiceAccounts))
	for _, sa := range in.ServiceAccounts {
		id := model.Identity{
			ID:     "gcp:" + sa.Email,
			Type:   model.IdentityServiceAccount,
			Source: "gcp_iam",
			Owner:  ownerFromDisplayName(sa.DisplayName),
		}
		for _, role := range rolesByEmail[sa.Email] {
			id.Permissions = append(id.Permissions, model.Permission{
				Name:  role,
				Admin: isAdminRole(role),
			})
		}
		id.Privileged = id.HasAdmin()
		out = append(out, id)
	}
	return out, nil
}

// isAdminRole flags GCP primitive and admin roles. roles/owner and roles/editor
// are broad standing privilege; any role path ending in "admin" qualifies.
func isAdminRole(role string) bool {
	switch role {
	case "roles/owner", "roles/editor":
		return true
	}
	return strings.HasSuffix(strings.ToLower(role), "admin")
}

// ownerFromDisplayName extracts an owner hint from a "team: ..." or
// "owner: ..." display name convention; empty otherwise.
func ownerFromDisplayName(name string) string {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"owner:", "team:", "contact:"} {
		if rest, ok := strings.CutPrefix(lower, prefix); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
