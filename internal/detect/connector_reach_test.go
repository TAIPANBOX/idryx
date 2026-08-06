package detect_test

import (
	"os"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/detect"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// These tests run the detector over a graph built by a real connector from a
// bundled fixture, rather than over identities built by hand in the test.
// That distinction is the whole point here: privilege_escalation's own unit
// test constructs permissions named "iam:PassRole",
// "iam.serviceAccounts.actAs" and "Microsoft.Authorization/roleAssignments/write",
// which are cloud ACTION strings, and no shipped connector produced a name of
// that shape. aws_iam emitted IAM POLICY NAMES, gcp_iam emitted ROLE names,
// azure emitted role definition names. The detector passed its own test while
// being unreachable from every input idryx can actually be given.

// fixtureGraph parses a bundled fixture with the real connector and returns
// the graph a CLI run would build from it.
func fixtureGraph(t *testing.T, path string, parse func([]byte) ([]model.Identity, error)) graph.Reader {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(ids) == 0 {
		t.Fatalf("%s produced no identities, so this test measured nothing", path)
	}
	g := graph.New(nil)
	for _, id := range ids {
		g.AddIdentity(id)
	}
	return g
}

func firedFor(d detect.Detector, g graph.Reader) map[string]bool {
	out := map[string]bool{}
	for _, a := range d.Detect(g) {
		out[a.IdentityID] = true
	}
	return out
}

// TestPrivilegeEscalationReachableFromBundledConnectors is the regression
// test for the unreachable detector: from each cloud connector's own bundled
// fixture, the identity that genuinely holds an escalation capability must be
// flagged, and the read-only one beside it must not.
func TestPrivilegeEscalationReachableFromBundledConnectors(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		parse   func([]byte) ([]model.Identity, error)
		want    []string
		wantNot []string
		why     string
	}{
		{
			name:    "aws_iam",
			fixture: "../../testdata/aws_iam.json",
			parse:   ingest.AWSIAM,
			want:    []string{"arn:aws:iam::123456789012:role/ci-deployer"},
			wantNot: []string{"arn:aws:iam::123456789012:role/ci-runner"},
			why:     "an inline policy document allowing iam:PassRole; the connector never read PolicyDocument at all",
		},
		{
			name:    "gcp_iam",
			fixture: "../../testdata/gcp_iam.json",
			parse:   ingest.GCPIAM,
			want:    []string{"gcp:ci-deployer@my-proj.iam.gserviceaccount.com"},
			wantNot: []string{"gcp:metrics-reader@my-proj.iam.gserviceaccount.com"},
			why:     "roles/owner contains iam.serviceAccounts.actAs; the connector emitted the role name and nothing knew what is inside it",
		},
		{
			name:    "azure",
			fixture: "../../testdata/azure.json",
			parse:   ingest.Azure,
			want:    []string{"azure:11111111-1111-1111-1111-111111111111"},
			wantNot: []string{"azure:33333333-3333-3333-3333-333333333333"},
			why:     "the Owner built-in role contains Microsoft.Authorization/roleAssignments/write; the connector emitted \"Owner\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := fixtureGraph(t, tc.fixture, tc.parse)
			fired := firedFor(detectors.NewPrivilegeEscalation(), g)
			for _, id := range tc.want {
				if !fired[id] {
					t.Errorf("privilege_escalation did not fire for %s (%s)", id, tc.why)
				}
			}
			for _, id := range tc.wantNot {
				if fired[id] {
					t.Errorf("privilege_escalation fired for %s, which holds no escalation capability", id)
				}
			}
		})
	}
}

// TestAdminEquivalenceFromAPolicyDocumentNotAName is the related half: admin
// equivalence was decided purely by string matching on policy and role names
// (isAdminPolicy: "administratoraccess" or "admin"), so a customer-managed
// policy granting "Action": "*" on "Resource": "*" under any ordinary name
// was invisible to every admin-based detector: excessive_agency,
// over_privileged_nhi, runaway_agent, attestation_missing and shadow_mcp all
// key on Identity.HasAdmin().
func TestAdminEquivalenceFromAPolicyDocumentNotAName(t *testing.T) {
	g := fixtureGraph(t, "../../testdata/aws_iam.json", ingest.AWSIAM)

	const id = "arn:aws:iam::123456789012:role/app-config"
	var found *model.Identity
	for _, got := range g.Identities() {
		if got.ID == id {
			found = got
		}
	}
	if found == nil {
		t.Fatalf("%s missing from the fixture graph", id)
	}
	if !found.HasAdmin() {
		t.Errorf("%s holds a customer-managed policy allowing * on *, and HasAdmin() is false: every admin-based detector is blind to it", id)
	}
	if !found.Privileged {
		t.Errorf("%s is admin-equivalent and not marked privileged", id)
	}

	if fired := firedFor(detectors.NewOverPrivilegedNHI(), g); !fired[id] {
		t.Errorf("over_privileged_nhi did not fire for %s, whose policy document grants everything on everything", id)
	}
}

// TestPolicyDocumentActionsDoNotChangeThePermissionInventory guards the
// blast radius of the fix. Actions derived from a policy document hang off
// the permission that granted them; they must not become permissions in
// their own right, because least_privilege lists unused permission names to
// an operator and remediation generates Terraform from them, and an action
// string in either place is noise at best and a wrong diff at worst.
func TestPolicyDocumentActionsDoNotChangeThePermissionInventory(t *testing.T) {
	g := fixtureGraph(t, "../../testdata/aws_iam.json", ingest.AWSIAM)
	for _, id := range g.Identities() {
		for _, p := range id.Permissions {
			if p.Name == "" {
				t.Errorf("%s has a permission with no name", id.ID)
			}
			for _, a := range p.Actions {
				if a == p.Name {
					continue
				}
				for _, other := range id.Permissions {
					if other.Name == a {
						t.Errorf("%s: action %q from policy %q also became a permission of its own", id.ID, a, p.Name)
					}
				}
			}
		}
	}
}
