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
				Name:    role,
				Admin:   isAdminRole(role),
				Actions: escalationPermissionsInRole(role),
			})
		}
		id.Privileged = id.HasAdmin()
		out = append(out, id)
	}
	return out, nil
}

// gcpAuditEntry is the subset of a GCP Cloud Audit Log entry idryx reads. The
// principal that acted and the service it called are enough to mark which granted
// roles a service account has actually exercised.
type gcpAuditEntry struct {
	ProtoPayload struct {
		ServiceName        string `json:"serviceName"`
		MethodName         string `json:"methodName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
	} `json:"protoPayload"`
}

// gcpAuditEntries accepts both a top-level JSON array of entries and the
// {"entries":[...]} envelope produced by `gcloud logging read --format=json`.
func gcpAuditEntries(data []byte) ([]gcpAuditEntry, error) {
	var wrap struct {
		Entries []gcpAuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &wrap); err == nil && wrap.Entries != nil {
		return wrap.Entries, nil
	}
	var arr []gcpAuditEntry
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

// GCPAuditUsage returns a map of service-account identity ID ("gcp:<email>") to
// the set of GCP service prefixes (e.g. "storage", "compute") that account was
// observed calling. Keyed to match identities produced by GCPIAM.
func GCPAuditUsage(data []byte) (map[string]map[string]bool, error) {
	entries, err := gcpAuditEntries(data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]bool)
	for _, e := range entries {
		email := e.ProtoPayload.AuthenticationInfo.PrincipalEmail
		if email == "" || e.ProtoPayload.ServiceName == "" {
			continue
		}
		key := "gcp:" + email
		svc := serviceFromEventSource(e.ProtoPayload.ServiceName)
		if out[key] == nil {
			out[key] = make(map[string]bool)
		}
		out[key][svc] = true
	}
	return out, nil
}

// GCPIAMWithUsage parses gcp_iam inventory and enriches each role with Cloud
// Audit Log usage. A role is marked Used when the service account was observed
// calling the GCP service that role governs, enabling the least-privilege
// detector to flag never-exercised roles on GCP as it does on AWS.
func GCPIAMWithUsage(iamData, auditData []byte) ([]model.Identity, error) {
	ids, err := GCPIAM(iamData)
	if err != nil {
		return nil, err
	}
	usage, err := GCPAuditUsage(auditData)
	if err != nil {
		return nil, err
	}
	for i := range ids {
		usedSvcs := usage[ids[i].ID]
		hasAny := len(usedSvcs) > 0
		for j := range ids[i].Permissions {
			p := &ids[i].Permissions[j]
			for _, svc := range servicesFromRole(p.Name) {
				if (svc == "*" && hasAny) || usedSvcs[svc] {
					p.Used = true
					break
				}
			}
		}
	}
	return ids, nil
}

// servicesFromRole infers the GCP service prefixes a role governs. Primitive
// roles (owner/editor/viewer) span every service and return ["*"]; predefined
// roles encode their service as "roles/<service>.<tier>". Returns nil when no
// service hint is present (e.g. opaque custom roles).
func servicesFromRole(role string) []string {
	lower := strings.ToLower(role)
	switch lower {
	case "roles/owner", "roles/editor", "roles/viewer":
		return []string{"*"}
	}
	r := strings.TrimPrefix(lower, "roles/")
	if i := strings.Index(r, "."); i > 0 {
		return []string{r[:i]}
	}
	return nil
}

// gcpRoleEscalationPermissions records, for the GCP roles that carry one, the
// escalation-relevant permissions the role contains. A GCP project IAM policy
// (`gcloud projects get-iam-policy`) binds ROLES to members and says nothing
// about what is inside a role, so without this table the only thing idryx
// knew about roles/owner was its name, and the privilege_escalation detector,
// which keys on permission strings, could never fire from this connector.
//
// Scope and honesty about it: these are predefined roles only, and only the
// permissions that appear in the detector's own escalation list. It is a
// hand-maintained map (@claude, 2026-08-06), not a fetch of the live role
// definition: this connector is offline by design and reads the export it was
// given. Google can change what a predefined role contains, and a CUSTOM
// role's contents are not in this input at all, so a custom role granting
// iam.serviceAccounts.actAs is still invisible here. Both limits are stated
// in VALIDATION.md rather than papered over.
var gcpRoleEscalationPermissions = map[string][]string{
	// Primitive roles. Owner and Editor both carry service-account
	// impersonation and key creation, which is the classic GCP escalation
	// path (act as a more privileged service account).
	"roles/owner": {
		"iam.serviceaccounts.actas",
		"iam.serviceaccounts.getaccesstoken",
		"iam.serviceaccounts.getopenidtoken",
		"iam.serviceaccounts.implicitdelegation",
		"iam.serviceaccounts.signblob",
		"iam.serviceaccounts.signjwt",
		"iam.serviceaccounts.setiampolicy",
		"iam.serviceaccountkeys.create",
	},
	"roles/editor": {
		"iam.serviceaccounts.actas",
		"iam.serviceaccountkeys.create",
	},
	// The service-account roles, which exist precisely to delegate
	// impersonation.
	"roles/iam.serviceaccountuser": {
		"iam.serviceaccounts.actas",
	},
	"roles/iam.serviceaccounttokencreator": {
		"iam.serviceaccounts.getaccesstoken",
		"iam.serviceaccounts.getopenidtoken",
		"iam.serviceaccounts.implicitdelegation",
		"iam.serviceaccounts.signblob",
		"iam.serviceaccounts.signjwt",
	},
	"roles/iam.serviceaccountkeyadmin": {
		"iam.serviceaccountkeys.create",
	},
	"roles/iam.serviceaccountadmin": {
		"iam.serviceaccounts.setiampolicy",
	},
	"roles/iam.workloadidentityuser": {
		"iam.serviceaccounts.getaccesstoken",
		"iam.serviceaccounts.getopenidtoken",
	},
}

// escalationPermissionsInRole returns the escalation-relevant permissions a
// GCP role is known to contain, or nil when the role is not in the table
// (which means "not known", never "contains none").
func escalationPermissionsInRole(role string) []string {
	perms, ok := gcpRoleEscalationPermissions[strings.ToLower(role)]
	if !ok {
		return nil
	}
	return normalizeActions(perms)
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
