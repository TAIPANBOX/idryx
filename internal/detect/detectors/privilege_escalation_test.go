package detectors

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestPrivilegeEscalation(t *testing.T) {
	withFixedNow(t)

	g := graph.New(nil)
	// AWS service account with iam:PassRole
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::123456789012:role/deployer",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "iam:PassRole", Admin: false},
			{Name: "S3Read", Admin: false},
		},
	})
	// GCP service account with actAs
	g.AddIdentity(model.Identity{
		ID:     "gcp:my-sa@my-proj.iam.gserviceaccount.com",
		Type:   model.IdentityServiceAccount,
		Source: "gcp_iam",
		Permissions: []model.Permission{
			{Name: "iam.serviceAccounts.actAs", Admin: false},
		},
	})
	// Azure service principal with role assignments write
	g.AddIdentity(model.Identity{
		ID:     "azure:11111111-1111-1111-1111-111111111111",
		Type:   model.IdentityServiceAccount,
		Source: "azure",
		Permissions: []model.Permission{
			{Name: "Microsoft.Authorization/roleAssignments/write", Admin: false},
		},
	})
	// Benign identity
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::123456789012:role/monitoring",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "CloudWatchReadOnly", Admin: false},
		},
	})
	// Human identity with iam:PassRole (should be ignored, as this detector is for NHIs only)
	g.AddIdentity(model.Identity{
		ID:   "alice@example.com",
		Type: model.IdentityHuman,
		Permissions: []model.Permission{
			{Name: "iam:PassRole", Admin: false},
		},
	})

	got := detect(NewPrivilegeEscalation(), g)

	if a, ok := got["arn:aws:iam::123456789012:role/deployer"]; !ok {
		t.Error("expected AWS deployer role to be flagged for privilege escalation")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", a.Severity)
	}

	if a, ok := got["gcp:my-sa@my-proj.iam.gserviceaccount.com"]; !ok {
		t.Error("expected GCP service account to be flagged for privilege escalation")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", a.Severity)
	}

	if a, ok := got["azure:11111111-1111-1111-1111-111111111111"]; !ok {
		t.Error("expected Azure service principal to be flagged for privilege escalation")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", a.Severity)
	}

	if _, ok := got["arn:aws:iam::123456789012:role/monitoring"]; ok {
		t.Error("monitoring role with benign permissions should not be flagged")
	}

	if _, ok := got["alice@example.com"]; ok {
		t.Error("human identity should not be flagged")
	}
}

func TestMatchDangerous(t *testing.T) {
	cases := []struct {
		perm string
		want bool
	}{
		// Exact matches.
		{"iam:passrole", true},
		{"iam.serviceaccounts.actas", true},
		{"microsoft.authorization/roleassignments/write", true},
		// Embedded with resource or ARN context — still dangerous.
		{"iam:passrole on arn:aws:iam::123456789012:role/deploy", true},
		{"sts/iam:passrole", true},
		{"microsoft.authorization/roleassignments/write/extra", true},
		// Superstrings that merely contain a dangerous name — must NOT match.
		{"iam:passrolespecial", false},
		{"iam:passrole2", false},
		{"iam:createaccesskeygrant", false},
		{"iam.serviceaccounts.actassistant", false},
		{"custom:iam:putrolepolicysafely", false},
		// Benign permissions.
		{"s3:getobject", false},
		{"cloudwatchreadonly", false},
	}
	for _, tc := range cases {
		if _, got := matchDangerous(tc.perm); got != tc.want {
			t.Errorf("matchDangerous(%q) = %v, want %v", tc.perm, got, tc.want)
		}
	}
}
