package ingest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestEveryConnectorRefusesInputThatIsNotJSON: a file that does not parse
// is an error from every connector, never an empty and silent graph.
func TestEveryConnectorRefusesInputThatIsNotJSON(t *testing.T) {
	bad := []byte("{not json")
	valid := []byte(`{}`)
	checks := map[string]func() error{
		"agents":          func() error { _, _, err := Agents(bad); return err },
		"aws_iam":         func() error { _, err := AWSIAM(bad); return err },
		"azure":           func() error { _, err := Azure(bad); return err },
		"cloudtrail":      func() error { _, _, err := CloudTrail(bad); return err },
		"ct usage":        func() error { _, err := CloudTrailUsage(bad); return err },
		"egress":          func() error { _, _, err := Egress(bad); return err },
		"entra":           func() error { _, _, err := Entra(bad); return err },
		"gcp_iam":         func() error { _, err := GCPIAM(bad); return err },
		"gcp audit":       func() error { _, err := GCPAuditUsage(bad); return err },
		"mcp":             func() error { _, err := MCP(bad); return err },
		"okta":            func() error { _, _, err := Okta(bad); return err },
		"aws+ct, bad iam": func() error { _, err := AWSSIAMWithUsage(bad, valid); return err },
		"aws+ct, bad ct":  func() error { _, err := AWSSIAMWithUsage(valid, bad); return err },
		"gcp+audit, bad iam": func() error {
			_, err := GCPIAMWithUsage(bad, []byte(`[]`))
			return err
		},
		"gcp+audit, bad audit": func() error { _, err := GCPIAMWithUsage(valid, bad); return err },
	}
	for name, check := range checks {
		if err := check(); err == nil {
			t.Errorf("%s: malformed input accepted", name)
		}
	}
}

// TestEntraReadsTheBareArrayExport: Entra sign-ins come either wrapped in
// {"value": [...]} (Graph) or as a bare array (a portal export).
func TestEntraReadsTheBareArrayExport(t *testing.T) {
	data := []byte(`[{"userPrincipalName":"amy@x.com","createdDateTime":"2026-01-01T00:00:00Z","ipAddress":"198.51.100.1"}]`)
	events, rep, err := Entra(data)
	if err != nil {
		t.Fatalf("Entra(bare array): %v", err)
	}
	if len(events) != 1 || events[0].IdentityID != "amy@x.com" || rep.Records != 1 {
		t.Fatalf("events = %+v, report %+v; want amy@x.com once", events, rep)
	}
	// Neither shape: a string fails both decoders, and an object with no
	// "value" is not a bare array either.
	for _, raw := range []string{`"a string"`, `{"other":1}`} {
		if _, _, err := Entra([]byte(raw)); err == nil {
			t.Errorf("%s accepted as an Entra export", raw)
		}
	}
}

func TestOktaEventTypesMapToLoginMFAOrOther(t *testing.T) {
	cases := map[string]model.EventType{
		"user.session.start":                  model.EventLogin,
		"user.authentication.sso":             model.EventLogin,
		"system.push.send_factor_verify_push": model.EventMFAChallenge,
		"user.mfa.attempt_bypass":             model.EventMFAChallenge,
		"user.mfa.factor.activate":            model.EventMFAChallenge,
		"policy.rule.update":                  model.EventOther,
		"":                                    model.EventOther,
	}
	for in, want := range cases {
		if got := mapType(in); got != want {
			t.Errorf("mapType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeARNOnlyRewritesWellFormedSessions: a session ARN becomes the
// role it assumed; anything that does not have the full shape is left alone
// rather than mangled into a role that does not exist.
func TestNormalizeARNOnlyRewritesWellFormedSessions(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::123:assumed-role/etl/session-1": "arn:aws:iam::123:role/etl",
		"arn:aws:iam::123:user/bob":                   "arn:aws:iam::123:user/bob",
		"sts::assumed-role/etl/s":                     "sts::assumed-role/etl/s",
		"arn:aws:sts::assumed-role/x:123:no-slash":    "arn:aws:sts::assumed-role/x:123:no-slash",
		"arn:aws:sts::123:assumed-role/etl":           "arn:aws:iam::123:role/etl",
	}
	for in, want := range cases {
		if got := normalizeARN(in); got != want {
			t.Errorf("normalizeARN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCloudTrailUsageSkipsRecordsWithoutAnActorOrService(t *testing.T) {
	data := []byte(`{"Records":[
		{"eventSource":"s3.amazonaws.com","userIdentity":{"arn":""}},
		{"eventSource":"","userIdentity":{"arn":"arn:aws:iam::1:user/a"}},
		{"eventSource":"EC2","userIdentity":{"arn":"arn:aws:iam::1:user/a"}},
		{"eventSource":"s3.amazonaws.com","userIdentity":{"arn":"arn:aws:sts::1:assumed-role/r/s"}}
	]}`)
	usage, err := CloudTrailUsage(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]bool{
		"arn:aws:iam::1:user/a": {"ec2": true},
		"arn:aws:iam::1:role/r": {"s3": true},
	}
	if !reflect.DeepEqual(usage, want) {
		t.Errorf("usage = %v, want %v", usage, want)
	}
}

func TestGCPAuditUsageSkipsEntriesWithoutAPrincipalOrService(t *testing.T) {
	data := []byte(`[
		{"protoPayload":{"serviceName":"storage.googleapis.com","authenticationInfo":{"principalEmail":""}}},
		{"protoPayload":{"serviceName":"","authenticationInfo":{"principalEmail":"sa@p.iam.gserviceaccount.com"}}},
		{"protoPayload":{"serviceName":"compute.googleapis.com","authenticationInfo":{"principalEmail":"sa@p.iam.gserviceaccount.com"}}}
	]`)
	usage, err := GCPAuditUsage(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]bool{"gcp:sa@p.iam.gserviceaccount.com": {"compute": true}}
	if !reflect.DeepEqual(usage, want) {
		t.Errorf("usage = %v, want %v", usage, want)
	}
}

// TestAgentsMarksOnlyObservedToolsAsUsed: usedTools is evidence of use per
// tool; a tool not in it stays unused, which is what least_privilege reads.
func TestAgentsMarksOnlyObservedToolsAsUsed(t *testing.T) {
	data := []byte(`{"agents":[{"id":"agent:a","tools":["jira_read","s3_delete"],"usedTools":["jira_read","not_granted"]}]}`)
	ids, _, err := Agents(data)
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, p := range ids[0].Permissions {
		used[p.Name] = p.Used
	}
	want := map[string]bool{"jira_read": true, "s3_delete": false}
	if !reflect.DeepEqual(used, want) {
		t.Errorf("used = %v, want %v (a used tool that was never granted adds no grant)", used, want)
	}
}

func TestParseAWSTimeTreatsAnUnreadableTimeAsUnknown(t *testing.T) {
	if got := parseAWSTime("2026-01-02T03:04:05Z"); got.IsZero() {
		t.Error("an RFC3339 time read as unknown")
	}
	for _, s := range []string{"", "yesterday", "2026-01-02 03:04:05"} {
		if got := parseAWSTime(s); !got.IsZero() {
			t.Errorf("parseAWSTime(%q) = %s, want the zero time", s, got)
		}
	}
}

// TestManagedPolicyIndexReadsOnlyTheDefaultVersion: only the version AWS
// enforces counts, a policy with no ARN cannot be matched to an attachment,
// and a document that does not decode grants nothing rather than everything.
func TestManagedPolicyIndexReadsOnlyTheDefaultVersion(t *testing.T) {
	adminDoc := json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	readDoc := json.RawMessage(`{"Statement":[{"Effect":"Allow","Action":["S3:GetObject"," ",""],"Resource":["arn:aws:s3:::b/*"]}]}`)
	idx := managedPolicyIndex([]awsManagedPolicy{
		{PolicyName: "no-arn", PolicyVersionList: []awsPolicyVersion{{Document: adminDoc, IsDefaultVersion: true}}},
		{PolicyName: "p", Arn: "arn:p", DefaultVersionID: "v2", PolicyVersionList: []awsPolicyVersion{
			{Document: adminDoc, VersionID: "v1"},
			{Document: readDoc, VersionID: "v2"},
		}},
		{PolicyName: "broken", Arn: "arn:broken", PolicyVersionList: []awsPolicyVersion{{Document: json.RawMessage(`"%zz{"`), IsDefaultVersion: true}}},
	})
	if len(idx) != 1 {
		t.Fatalf("index holds %d policies, want only arn:p: %v", len(idx), idx)
	}
	g := idx["arn:p"]
	if g.admin {
		t.Error("an old admin version made the policy admin")
	}
	if !reflect.DeepEqual(g.actions, []string{"s3:getobject"}) {
		t.Errorf("actions = %v, want [s3:getobject] with blanks dropped", g.actions)
	}
}

func TestPolicyActionSetsRefuseANonStringShape(t *testing.T) {
	var s awsStringSet
	if err := json.Unmarshal([]byte(`42`), &s); err == nil {
		t.Errorf("a number decoded as an action set: %v", s)
	}
	if err := json.Unmarshal([]byte(`"s3:*"`), &s); err != nil || !reflect.DeepEqual([]string(s), []string{"s3:*"}) {
		t.Errorf("a bare string = %v, %v", s, err)
	}
}

func TestDecodePolicyDocumentRefusesAnUndecodableString(t *testing.T) {
	for _, raw := range []string{`"`, `"not a policy"`, `null`, ``} {
		if _, ok := decodePolicyDocument(json.RawMessage(raw)); ok {
			t.Errorf("decodePolicyDocument(%s) reported a document", raw)
		}
	}
	doc, ok := decodePolicyDocument(json.RawMessage(`"%7B%22Statement%22%3A%5B%5D%7D"`))
	if !ok || doc.Statement == nil {
		t.Errorf("a URL-encoded document did not decode: %+v %v", doc, ok)
	}
}

func TestNormalizeActionsDropsBlanksAndRepeats(t *testing.T) {
	got := normalizeActions([]string{" IAM:PassRole ", "iam:passrole", "", "  ", "s3:GetObject"})
	if strings.Join(got, ",") != "iam:passrole,s3:getobject" {
		t.Errorf("normalizeActions = %v", got)
	}
}
