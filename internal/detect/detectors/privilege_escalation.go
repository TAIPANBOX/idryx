package detectors

import (
	"fmt"
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
var dangerousPermissions = map[string]string{
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

	// Azure
	"microsoft.authorization/roleassignments/write":       "Azure: Allow creating new role assignments",
	"microsoft.authorization/roledefinitions/write":       "Azure: Allow creating new custom role definitions",
	"microsoft.resources/deployments/write":               "Azure: Allow running resource templates with admin privileges",
	"microsoft.compute/virtualmachines/runcommand/action": "Azure: Allow running arbitrary shell commands inside VMs",
}

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
	for k, desc := range dangerousPermissions {
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

func (d *PrivilegeEscalation) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		if !id.IsNHI() {
			continue
		}

		for _, p := range id.Permissions {
			matchedDesc, found := matchDangerous(strings.ToLower(p.Name))
			if found {
				alerts = append(alerts, model.Alert{
					Detector:   d.Name(),
					IdentityID: id.ID,
					Severity:   model.SeverityHigh,
					Time:       now(),
					Summary:    fmt.Sprintf("NHI holds dangerous escalation permission %q (%s)", p.Name, matchedDesc),
				})
			}
		}
	}
	return alerts
}
