package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestAWSIAM(t *testing.T) {
	data := []byte(`{
	  "UserDetailList": [
	    {"UserName":"deploy","Arn":"arn:aws:iam::1:user/deploy","CreateDate":"2024-01-01T00:00:00Z",
	     "Tags":[{"Key":"owner","Value":"platform"}],
	     "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}],
	     "UserPolicyList":[]}
	  ],
	  "RoleDetailList": [
	    {"RoleName":"reader","Arn":"arn:aws:iam::1:role/reader","CreateDate":"2025-06-01T00:00:00Z",
	     "AttachedManagedPolicies":[{"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}],
	     "RolePolicyList":[{"PolicyName":"inline-extra"}],
	     "RoleLastUsed":{"LastUsedDate":"2026-05-01T00:00:00Z"}}
	  ]
	}`)

	ids, err := AWSIAM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	deploy := byID["arn:aws:iam::1:user/deploy"]
	if deploy.Type != model.IdentityServiceAccount || deploy.Source != "aws_iam" {
		t.Errorf("deploy type/source = %v/%q", deploy.Type, deploy.Source)
	}
	if deploy.Owner != "platform" {
		t.Errorf("deploy owner = %q, want platform", deploy.Owner)
	}
	if !deploy.HasAdmin() || !deploy.Privileged {
		t.Error("deploy should be admin/privileged")
	}

	reader := byID["arn:aws:iam::1:role/reader"]
	if reader.HasAdmin() {
		t.Error("reader should not be admin")
	}
	if len(reader.Permissions) != 2 {
		t.Errorf("reader perms = %d, want 2 (managed + inline)", len(reader.Permissions))
	}
	if reader.LastUsed.IsZero() {
		t.Error("reader should have a LastUsed date")
	}
}
