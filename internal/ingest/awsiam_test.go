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

// TestAWSIAMCarriesRealPolicyARN is the regression test for the discarded-ARN
// bug: PolicyArn is read off the wire (isAdminPolicy uses it) but never
// stored on the identity, so remediation later has to guess it back and
// guesses wrong for customer-managed policies. AWSIAM must carry the real
// ARN through onto Permission.ARN, for both an AWS-managed policy (the
// arn:aws:iam::aws:policy/<name> shape) and a customer-managed one
// (arn:aws:iam::<account-id>:policy/<name>, which cannot be reconstructed
// from the name alone). Inline policies have no ARN in AWS, so ARN must stay
// empty for those.
func TestAWSIAMCarriesRealPolicyARN(t *testing.T) {
	data := []byte(`{
	  "RoleDetailList": [
	    {"RoleName":"data-pipeline","Arn":"arn:aws:iam::123456789012:role/data-pipeline","CreateDate":"2024-01-01T00:00:00Z",
	     "AttachedManagedPolicies":[
	       {"PolicyName":"CustomDataAccess","PolicyArn":"arn:aws:iam::123456789012:policy/CustomDataAccess"},
	       {"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}
	     ],
	     "RolePolicyList":[{"PolicyName":"inline-extra"}]}
	  ]
	}`)

	ids, err := AWSIAM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}

	byName := map[string]model.Permission{}
	for _, p := range ids[0].Permissions {
		byName[p.Name] = p
	}

	custom, ok := byName["CustomDataAccess"]
	if !ok {
		t.Fatal("missing CustomDataAccess permission")
	}
	if custom.ARN != "arn:aws:iam::123456789012:policy/CustomDataAccess" {
		t.Errorf("customer-managed policy ARN = %q, want the real account-scoped ARN", custom.ARN)
	}

	managed, ok := byName["ReadOnlyAccess"]
	if !ok {
		t.Fatal("missing ReadOnlyAccess permission")
	}
	if managed.ARN != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Errorf("aws-managed policy ARN = %q, want the real aws-managed ARN", managed.ARN)
	}

	inline, ok := byName["inline-extra"]
	if !ok {
		t.Fatal("missing inline-extra permission")
	}
	if inline.ARN != "" {
		t.Errorf("inline policy ARN = %q, want empty (inline policies have no ARN)", inline.ARN)
	}
}
