package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// azureInventory is the input idryx reads for the azure source: service
// principals (from `az ad sp list`) and role assignments (from
// `az role assignment list`). Assignments map a role to a principal by its
// object ID; idryx attaches roles to the principals they name.
type azureInventory struct {
	ServicePrincipals []azureSP             `json:"servicePrincipals"`
	RoleAssignments   []azureRoleAssignment `json:"roleAssignments"`
}

type azureSP struct {
	ID                     string   `json:"id"`    // object ID
	AppID                  string   `json:"appId"` // application (client) ID
	DisplayName            string   `json:"displayName"`
	AccountEnabled         bool     `json:"accountEnabled"`
	Owners                 []string `json:"owners"` // owner UPNs/emails, when resolved
	PasswordCredentialEnds []string `json:"passwordCredentialEndDates"`
}

type azureRoleAssignment struct {
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionName"` // human role name, e.g. "Owner"
}

// Azure parses the azure inventory into service-principal identities. Roles
// Owner / Contributor / *Administrator are treated as admin-equivalent. An
// expired password credential is surfaced as the LastUsed proxy is unavailable;
// the principal's enabled flag and owners drive staleness/orphan detection.
func Azure(data []byte) ([]model.Identity, error) {
	var in azureInventory
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}

	rolesByPrincipal := map[string][]string{}
	for _, a := range in.RoleAssignments {
		rolesByPrincipal[a.PrincipalID] = append(rolesByPrincipal[a.PrincipalID], a.RoleDefinitionID)
	}

	out := make([]model.Identity, 0, len(in.ServicePrincipals))
	for _, sp := range in.ServicePrincipals {
		id := model.Identity{
			ID:     "azure:" + sp.ID,
			Type:   model.IdentityServiceAccount,
			Source: "azure",
			Owner:  firstNonEmpty(sp.Owners),
		}
		for _, role := range rolesByPrincipal[sp.ID] {
			id.Permissions = append(id.Permissions, model.Permission{
				Name:    role,
				Admin:   isAzureAdminRole(role),
				Actions: escalationActionsInAzureRole(role),
			})
		}
		// The most recent credential expiry stands in for a freshness signal:
		// a long-expired secret on an enabled principal is a stale-credential risk.
		if t := latestTime(sp.PasswordCredentialEnds); !t.IsZero() {
			id.LastUsed = t
		}
		id.Privileged = id.HasAdmin()
		out = append(out, id)
	}
	return out, nil
}

// azureRoleEscalationActions records, for the Azure built-in roles that carry
// them, the escalation-relevant actions the role definition contains.
// `az role assignment list` reports a roleDefinitionName ("Owner",
// "Contributor") and nothing about the actions behind it, so without this
// table the privilege_escalation detector, which keys on action strings,
// could never fire from this connector.
//
// Scope, stated: built-in roles only, and only the actions in the detector's
// own escalation list. Hand-maintained (@claude, 2026-08-06) from the
// documented built-in role definitions rather than fetched live, because this
// connector reads an export and never calls Azure. A CUSTOM role definition's
// actions are not in this input at all, so a custom role granting
// Microsoft.Authorization/roleAssignments/write is still invisible here.
//
// Contributor is the one worth reading twice: it grants everything EXCEPT
// authorization writes, so it does not get roleAssignments/write, and giving
// it one would be a false accusation on one of the most widely assigned roles
// in Azure. It does get deployments/write and runCommand/action, which are
// real escalation paths (deploy a template, or run a command inside a VM, as
// a more privileged identity).
var azureRoleEscalationActions = map[string][]string{
	"owner": {
		"microsoft.authorization/roleassignments/write",
		"microsoft.authorization/roledefinitions/write",
		"microsoft.resources/deployments/write",
		"microsoft.compute/virtualmachines/runcommand/action",
	},
	"user access administrator": {
		"microsoft.authorization/roleassignments/write",
		"microsoft.authorization/roledefinitions/write",
	},
	"role based access control administrator": {
		"microsoft.authorization/roleassignments/write",
	},
	"contributor": {
		"microsoft.resources/deployments/write",
		"microsoft.compute/virtualmachines/runcommand/action",
	},
	"virtual machine contributor": {
		"microsoft.compute/virtualmachines/runcommand/action",
	},
}

// escalationActionsInAzureRole returns the escalation-relevant actions an
// Azure built-in role is known to contain, or nil when the role is not in the
// table (which means "not known", never "contains none").
func escalationActionsInAzureRole(role string) []string {
	actions, ok := azureRoleEscalationActions[strings.ToLower(strings.TrimSpace(role))]
	if !ok {
		return nil
	}
	return normalizeActions(actions)
}

// isAzureAdminRole flags built-in roles that grant broad control.
func isAzureAdminRole(role string) bool {
	switch role {
	case "Owner", "Contributor", "User Access Administrator":
		return true
	}
	return strings.Contains(strings.ToLower(role), "administrator")
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// latestTime parses RFC3339 timestamps and returns the most recent; zero if none
// parse.
func latestTime(ss []string) time.Time {
	var latest time.Time
	for _, s := range ss {
		if t, err := time.Parse(time.RFC3339, s); err == nil && t.After(latest) {
			latest = t
		}
	}
	return latest
}
