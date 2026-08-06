package detectors

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// PrivilegeEscalation flags non-human identities holding stealthy permissions
// that allow escalation to administrative/owner levels in AWS, GCP, and Azure.
type PrivilegeEscalation struct{}

func NewPrivilegeEscalation() *PrivilegeEscalation { return &PrivilegeEscalation{} }

func (d *PrivilegeEscalation) Name() string { return "privilege_escalation" }

// dangerousPermissions contains mappings of cloud-specific privilege escalation permissions.
var dangerousPermissions = map[string]string{ // #nosec G101 -- these are cloud IAM permission identifiers, not credentials
	// AWS
	"iam:createaccesskey":         "AWS: Allow generating new access keys for users",
	"iam:createuserpolicy":        "AWS: Allow inline user policy creation",
	"iam:putuserpolicy":           "AWS: Allow writing inline user policies",
	"iam:attachuserpolicy":        "AWS: Allow attaching managed user policies",
	"iam:attachrolepolicy":        "AWS: Allow attaching managed role policies",
	"iam:putrolepolicy":           "AWS: Allow writing inline role policies",
	"iam:createpolicyversion":     "AWS: Allow creating new IAM policy versions",
	"iam:setdefaultpolicyversion": "AWS: Allow changing active IAM policy version",
	"iam:passrole":                "AWS: Allow passing roles to AWS services",
	"iam:updateassumerolepolicy":  "AWS: Allow updating trust relationships",

	// GCP
	"iam.serviceaccounts.getaccesstoken":     "GCP: Allow acquiring short-lived SA access tokens",
	"iam.serviceaccounts.actas":              "GCP: Allow executing operations as the service account",
	"iam.serviceaccounts.implicitdelegation": "GCP: Allow delegation across projects",
	"iam.serviceaccounts.getopenidtoken":     "GCP: Allow acquiring OpenID Connect tokens",
	"iam.serviceaccounts.signblob":           "GCP: Allow signing raw payloads",
	"iam.serviceaccounts.signjwt":            "GCP: Allow signing JSON Web Tokens",
	"iam.serviceaccountkeys.create":          "GCP: Allow creating new Service Account keys",
	// setIamPolicy on a service account is one move from actAs: the holder
	// can grant itself impersonation and then use it.
	"iam.serviceaccounts.setiampolicy": "GCP: Allow granting itself impersonation on the service account",

	// Azure
	"microsoft.authorization/roleassignments/write":       "Azure: Allow creating new role assignments",
	"microsoft.authorization/roledefinitions/write":       "Azure: Allow creating new custom role definitions",
	"microsoft.resources/deployments/write":               "Azure: Allow running resource templates with admin privileges",
	"microsoft.compute/virtualmachines/runcommand/action": "Azure: Allow running arbitrary shell commands inside VMs",
}

// dangerousKeys is dangerousPermissions' keys in sorted order. The fallback
// scan below has to be deterministic: a permission string containing two
// escalation names would otherwise report whichever one Go's randomized map
// iteration reached first, and the same graph would produce a different
// summary between runs. Invariant 1 says a finding that cannot be reproduced
// from the same input is not evidence.
var dangerousKeys = func() []string {
	keys := make([]string, 0, len(dangerousPermissions))
	for k := range dangerousPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}()

// matchDangerous reports whether perm (already lowercased) refers to one of
// the known escalation permissions. Beyond an exact match, it accepts the
// permission embedded in a larger string (e.g. prefixed with an ARN or
// suffixed with a resource path) only when the match is bounded by
// non-identifier characters: "iam:passrole on role/deploy" matches, while
// "iam:passrolespecial" does not.
func matchDangerous(perm string) (string, bool) {
	if desc, ok := dangerousPermissions[perm]; ok {
		return desc, true
	}
	for _, k := range dangerousKeys {
		desc := dangerousPermissions[k]
		for idx := strings.Index(perm, k); idx >= 0; {
			startOK := idx == 0 || isPermBoundary(perm[idx-1])
			end := idx + len(k)
			endOK := end == len(perm) || isPermBoundary(perm[end])
			if startOK && endOK {
				return desc, true
			}
			next := strings.Index(perm[idx+1:], k)
			if next < 0 {
				break
			}
			idx += 1 + next
		}
	}
	return "", false
}

// isPermBoundary reports whether c cannot be part of a permission token, i.e.
// it separates the dangerous permission from an ARN prefix or resource suffix.
func isPermBoundary(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		return false
	}
	return true
}

// maxNamedInWildcard caps how many escalation permissions a wildcard grant
// names in its summary. The count is always stated in full.
const maxNamedInWildcard = 3

// matchDangerousAction is matchDangerous for a cloud ACTION string derived
// from a policy document or a role definition, which is the shape connectors
// now produce. Two things differ from matching a grant NAME:
//
//   - A trailing wildcard is expanded: "iam:*" holds every IAM escalation
//     action, and the summary names them (sorted, so the same graph gives the
//     same text) rather than reporting the wildcard and leaving the reader to
//     look them up.
//   - A bare "*" is NOT matched. It is a grant of everything, which the
//     connector already flags as admin-equivalent and over_privileged_nhi
//     already reports. This detector is for the escalation path that is
//     stealthy, an identity that is not admin and can become one, and an
//     identity that already holds every action is neither stealthy nor a
//     finding this detector adds anything to.
func matchDangerousAction(action string) (string, bool) {
	if action == "*" {
		return "", false
	}
	if prefix, ok := strings.CutSuffix(action, "*"); ok {
		var matched []string
		for _, k := range dangerousKeys {
			if strings.HasPrefix(k, prefix) {
				matched = append(matched, k)
			}
		}
		if len(matched) == 0 {
			return "", false
		}
		named := matched
		suffix := ""
		if len(named) > maxNamedInWildcard {
			named = named[:maxNamedInWildcard]
			suffix = fmt.Sprintf(" and %d more", len(matched)-maxNamedInWildcard)
		}
		return fmt.Sprintf("wildcard grant covering %d escalation permission(s): %s%s",
			len(matched), strings.Join(named, ", "), suffix), true
	}
	return matchDangerous(action)
}

func (d *PrivilegeEscalation) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() {
			continue
		}

		for _, p := range id.Permissions {
			// The grant's own name first, unchanged: some sources name a
			// permission with the action itself (an agent tool, an MCP
			// scope, a hand-built graph).
			if desc, found := matchDangerous(strings.ToLower(p.Name)); found {
				alerts = append(alerts, model.Alert{
					Detector:   d.Name(),
					IdentityID: id.ID,
					Severity:   model.SeverityHigh,
					Time:       now(),
					Summary:    fmt.Sprintf("NHI holds dangerous escalation permission %q (%s)", p.Name, desc),
				})
				continue
			}

			// Then what the grant actually allows: the actions a connector
			// derived from an AWS policy document, a GCP predefined role, or
			// an Azure built-in role definition. Without this the detector
			// was unreachable from every shipped connector, because none of
			// them ever produced a permission NAMED after a cloud action.
			// One alert per grant, on the first action that matches (Actions
			// arrive in a deterministic order from the connector), so a
			// policy allowing several escalation actions is one finding
			// about one grant rather than a burst of near-identical rows.
			for _, a := range p.Actions {
				desc, found := matchDangerousAction(strings.ToLower(a))
				if !found {
					continue
				}
				alerts = append(alerts, model.Alert{
					Detector:   d.Name(),
					IdentityID: id.ID,
					Severity:   model.SeverityHigh,
					Time:       now(),
					Summary: fmt.Sprintf("NHI holds dangerous escalation permission %q via grant %q (%s)",
						a, p.Name, desc),
				})
				break
			}
		}
	}
	return alerts
}
