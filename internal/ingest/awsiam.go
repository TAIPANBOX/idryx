package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// awsAuthDetails is the subset of `aws iam get-account-authorization-details`
// that idryx reads. Users and roles become non-human identities; their attached
// and inline policies become permissions.
type awsAuthDetails struct {
	UserDetailList []awsPrincipal `json:"UserDetailList"`
	RoleDetailList []awsPrincipal `json:"RoleDetailList"`
}

type awsPrincipal struct {
	UserName        string      `json:"UserName"`
	RoleName        string      `json:"RoleName"`
	Arn             string      `json:"Arn"`
	CreateDate      string      `json:"CreateDate"`
	Tags            []awsTag    `json:"Tags"`
	AttachedManaged []awsPolicy `json:"AttachedManagedPolicies"`
	UserPolicyList  []awsInline `json:"UserPolicyList"`
	RolePolicyList  []awsInline `json:"RolePolicyList"`
	RoleLastUsed    awsLastUsed `json:"RoleLastUsed"`
}

type awsTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type awsPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type awsInline struct {
	PolicyName string `json:"PolicyName"`
}

type awsLastUsed struct {
	LastUsedDate string `json:"LastUsedDate"`
}

// AWSIAM parses an IAM account authorization details document into identities.
// These carry no events; the NHI detectors reason over metadata and permissions.
func AWSIAM(data []byte) ([]model.Identity, error) {
	var d awsAuthDetails
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}

	var out []model.Identity
	for _, p := range d.UserDetailList {
		out = append(out, principalToIdentity(p, p.UserPolicyList))
	}
	for _, p := range d.RoleDetailList {
		out = append(out, principalToIdentity(p, p.RolePolicyList))
	}
	return out, nil
}

func principalToIdentity(p awsPrincipal, inline []awsInline) model.Identity {
	id := model.Identity{
		ID:      p.Arn,
		Type:    model.IdentityServiceAccount,
		Source:  "aws_iam",
		Owner:   ownerFromTags(p.Tags),
		Created: parseAWSTime(p.CreateDate),
	}
	if t := parseAWSTime(p.RoleLastUsed.LastUsedDate); !t.IsZero() {
		id.LastUsed = t
	}

	for _, m := range p.AttachedManaged {
		id.Permissions = append(id.Permissions, model.Permission{
			Name:  m.PolicyName,
			Admin: isAdminPolicy(m.PolicyName, m.PolicyArn),
		})
	}
	for _, in := range inline {
		id.Permissions = append(id.Permissions, model.Permission{
			Name:  in.PolicyName,
			Admin: isAdminPolicy(in.PolicyName, ""),
		})
	}
	id.Privileged = id.HasAdmin()
	return id
}

// isAdminPolicy flags AWS-managed AdministratorAccess and obvious admin grants.
func isAdminPolicy(name, arn string) bool {
	if arn == "arn:aws:iam::aws:policy/AdministratorAccess" {
		return true
	}
	n := strings.ToLower(name)
	return strings.Contains(n, "administratoraccess") || n == "admin"
}

func ownerFromTags(tags []awsTag) string {
	for _, t := range tags {
		switch strings.ToLower(t.Key) {
		case "owner", "team", "contact":
			return t.Value
		}
	}
	return ""
}

// parseAWSTime parses an IAM ISO-8601 timestamp; returns zero on empty/invalid.
func parseAWSTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
