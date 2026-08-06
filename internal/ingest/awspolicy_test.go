package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodePolicyDocumentAcceptsBothEncodings covers the two shapes a real
// export carries: the IAM API returns the document URL-encoded inside a JSON
// string, the AWS CLI decodes it into an object. An export produced either
// way has to read the same, because an operator does not know which one they
// have.
func TestDecodePolicyDocumentAcceptsBothEncodings(t *testing.T) {
	object := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`)
	encoded := json.RawMessage(`"%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3APassRole%22%2C%22Resource%22%3A%22*%22%7D%5D%7D"`)

	for name, raw := range map[string]json.RawMessage{"object": object, "url-encoded": encoded} {
		doc, ok := decodePolicyDocument(raw)
		if !ok {
			t.Fatalf("%s: document did not decode", name)
		}
		actions, _ := policyEffect(doc)
		if len(actions) != 1 || actions[0] != "iam:passrole" {
			t.Errorf("%s: actions = %v, want [iam:passrole]", name, actions)
		}
	}
}

func TestDecodePolicyDocumentRejectsWhatItCannotRead(t *testing.T) {
	for name, raw := range map[string]json.RawMessage{
		"absent":       nil,
		"null":         json.RawMessage(`null`),
		"not json":     json.RawMessage(`"%7Bnot-json"`),
		"wrong shape":  json.RawMessage(`[1,2,3]`),
		"empty string": json.RawMessage(`""`),
	} {
		if _, ok := decodePolicyDocument(raw); ok {
			t.Errorf("%s: decoded as a policy document; an unreadable document must yield no actions rather than wrong ones", name)
		}
	}
}

// TestPolicyEffect pins the subset of the policy language this reads, and
// in particular the two ways a naive reading would be dangerously wrong: a
// Deny counted as a grant, and a NotAction list read as the actions allowed.
func TestPolicyEffect(t *testing.T) {
	cases := []struct {
		name        string
		doc         string
		wantActions []string
		wantAdmin   bool
	}{
		{
			name:        "allow list of actions",
			doc:         `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ecs:RunTask"],"Resource":"arn:aws:iam::1:role/x"}]}`,
			wantActions: []string{"iam:passrole", "ecs:runtask"},
		},
		{
			name:        "star on star is administrator-equivalent",
			doc:         `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			wantActions: []string{"*"},
			wantAdmin:   true,
		},
		{
			name:        "star action on a scoped resource is not admin",
			doc:         `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket/*"}]}`,
			wantActions: []string{"*"},
		},
		{
			name:        "deny grants nothing",
			doc:         `{"Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`,
			wantActions: nil,
		},
		{
			name:        "NotAction is not a grant of the actions it names",
			doc:         `{"Statement":[{"Effect":"Allow","NotAction":"iam:PassRole","Resource":"*"}]}`,
			wantActions: nil,
			wantAdmin:   true, // everything except one action is still nearly everything
		},
		{
			name:        "duplicates collapse and case is normalized",
			doc:         `{"Statement":[{"Effect":"Allow","Action":["S3:GetObject","s3:getobject"],"Resource":"*"}]}`,
			wantActions: []string{"s3:getobject"},
		},
		{
			name:        "a service wildcard is carried through as written",
			doc:         `{"Statement":[{"Effect":"allow","Action":"iam:*","Resource":"*"}]}`,
			wantActions: []string{"iam:*"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, ok := decodePolicyDocument(json.RawMessage(tc.doc))
			if !ok {
				t.Fatal("document did not decode")
			}
			actions, admin := policyEffect(doc)
			if strings.Join(actions, ",") != strings.Join(tc.wantActions, ",") {
				t.Errorf("actions = %v, want %v", actions, tc.wantActions)
			}
			if admin != tc.wantAdmin {
				t.Errorf("admin = %v, want %v", admin, tc.wantAdmin)
			}
		})
	}
}

// TestManagedPolicyUsesTheDefaultVersion: a customer-managed policy carries
// every version it has ever had. Only the default one is in force, and
// reading an older, narrower version is how a policy that was widened last
// month still reads as narrow.
func TestManagedPolicyUsesTheDefaultVersion(t *testing.T) {
	data := []byte(`{
	  "RoleDetailList": [
	    {"RoleName":"app","Arn":"arn:aws:iam::1:role/app","CreateDate":"2025-01-01T00:00:00Z",
	     "AttachedManagedPolicies":[{"PolicyName":"AppAccess","PolicyArn":"arn:aws:iam::1:policy/AppAccess"}],
	     "RolePolicyList":[]}
	  ],
	  "Policies": [
	    {"PolicyName":"AppAccess","Arn":"arn:aws:iam::1:policy/AppAccess","DefaultVersionId":"v2",
	     "PolicyVersionList":[
	       {"VersionId":"v1","IsDefaultVersion":false,"Document":{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}},
	       {"VersionId":"v2","IsDefaultVersion":true,"Document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}
	     ]}
	  ]
	}`)

	ids, err := AWSIAM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || len(ids[0].Permissions) != 1 {
		t.Fatalf("unexpected shape: %+v", ids)
	}
	p := ids[0].Permissions[0]
	if !p.Admin {
		t.Error("the default version allows * on *, so the grant is admin-equivalent under an ordinary policy name")
	}
	if len(p.Actions) != 1 || p.Actions[0] != "*" {
		t.Errorf("actions = %v, want the default version's [*], not v1's", p.Actions)
	}
	if !ids[0].Privileged {
		t.Error("an admin-equivalent grant must mark the identity privileged")
	}
}

// TestManagedPolicyWithoutADocumentKeepsItsName is the honest-degradation
// case: an export produced with --filter User,Role has no Policies section,
// so an attached policy has a name and an ARN and no knowable contents. That
// must leave the grant intact with no actions, never drop it.
func TestManagedPolicyWithoutADocumentKeepsItsName(t *testing.T) {
	data := []byte(`{
	  "RoleDetailList": [
	    {"RoleName":"app","Arn":"arn:aws:iam::1:role/app","CreateDate":"2025-01-01T00:00:00Z",
	     "AttachedManagedPolicies":[{"PolicyName":"AppAccess","PolicyArn":"arn:aws:iam::1:policy/AppAccess"}],
	     "RolePolicyList":[]}
	  ]
	}`)

	ids, err := AWSIAM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids[0].Permissions) != 1 {
		t.Fatalf("permissions = %+v, want the grant kept", ids[0].Permissions)
	}
	p := ids[0].Permissions[0]
	if p.Name != "AppAccess" || p.ARN != "arn:aws:iam::1:policy/AppAccess" {
		t.Errorf("grant lost its identity: %+v", p)
	}
	if len(p.Actions) != 0 {
		t.Errorf("actions = %v, want none: nothing in this export says what the policy contains", p.Actions)
	}
	if p.Admin {
		t.Error("an unknown policy must not be assumed admin")
	}
}

// TestGCPRoleEscalationPermissions and its Azure counterpart hold the shape
// of the two hand-maintained tables: the roles that carry an escalation path
// name it, the ones that do not stay empty, and an unknown or custom role
// yields nothing rather than a guess.
func TestGCPRoleEscalationPermissions(t *testing.T) {
	if got := escalationPermissionsInRole("roles/owner"); len(got) == 0 {
		t.Error("roles/owner contains service-account impersonation and must say so")
	}
	if got := escalationPermissionsInRole("roles/iam.serviceAccountUser"); len(got) != 1 || got[0] != "iam.serviceaccounts.actas" {
		t.Errorf("roles/iam.serviceAccountUser = %v, want [iam.serviceaccounts.actas] (case-insensitive lookup)", got)
	}
	if got := escalationPermissionsInRole("roles/monitoring.viewer"); len(got) != 0 {
		t.Errorf("roles/monitoring.viewer = %v, want none", got)
	}
	if got := escalationPermissionsInRole("projects/p/roles/customThing"); len(got) != 0 {
		t.Errorf("a custom role's contents are not in this input; got %v", got)
	}
}

func TestAzureRoleEscalationActions(t *testing.T) {
	owner := escalationActionsInAzureRole("Owner")
	if len(owner) == 0 {
		t.Fatal("the Owner role contains roleAssignments/write and must say so")
	}
	contributor := escalationActionsInAzureRole("Contributor")
	for _, a := range contributor {
		if strings.HasPrefix(a, "microsoft.authorization/") {
			t.Errorf("Contributor was given %q; Contributor grants everything EXCEPT authorization writes, and this would be a false accusation on one of the most widely assigned roles in Azure", a)
		}
	}
	if len(contributor) == 0 {
		t.Error("Contributor still holds deployments/write and runCommand/action")
	}
	if got := escalationActionsInAzureRole("Reader"); len(got) != 0 {
		t.Errorf("Reader = %v, want none", got)
	}
	if got := escalationActionsInAzureRole("our-custom-role"); len(got) != 0 {
		t.Errorf("a custom role definition is not in this input; got %v", got)
	}
}
