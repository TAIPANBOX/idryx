package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestEntra(t *testing.T) {
	data := []byte(`{"value":[
		{"createdDateTime":"2026-05-29T10:00:00Z","userPrincipalName":"alice@example.com",
		 "ipAddress":"1.2.3.4","status":{"errorCode":0},
		 "deviceDetail":{"browser":"Edge","operatingSystem":"Windows"},
		 "location":{"city":"Kyiv","countryOrRegion":"Ukraine","geoCoordinates":{"latitude":50.45,"longitude":30.52}}},
		{"createdDateTime":"2026-05-29T11:00:00Z","userPrincipalName":"bob@example.com",
		 "ipAddress":"5.6.7.8","status":{"errorCode":50126},
		 "deviceDetail":{"browser":"Chrome","operatingSystem":"macOS"},
		 "location":{"city":"NY","countryOrRegion":"United States","geoCoordinates":{"latitude":40.7,"longitude":-74.0}}}
	]}`)
	events, rep, err := Entra(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].IdentityID != "alice@example.com" || events[0].Outcome != "SUCCESS" {
		t.Errorf("event0 = %+v", events[0])
	}
	if events[0].Type != model.EventLogin || events[0].Country != "Ukraine" {
		t.Errorf("event0 type/country = %v/%q", events[0].Type, events[0].Country)
	}
	if events[1].Outcome != "FAILURE" {
		t.Errorf("event1 outcome = %q, want FAILURE", events[1].Outcome)
	}
	if rep.Records != 2 || rep.Malformed != 0 {
		t.Errorf("rep = %+v, want {Records:2 Malformed:0} (no malformed rows in this fixture)", rep)
	}
}

// TestEntraMalformedTimestampSkippedAndCounted is the regression test for a
// silently truncated Entra sign-in log: an entry whose "createdDateTime"
// does not parse as RFC3339 was dropped with a bare `continue` and nothing
// surfaced how many were skipped.
func TestEntraMalformedTimestampSkippedAndCounted(t *testing.T) {
	data := []byte(`{"value":[
		{"createdDateTime":"2026-05-29T10:00:00Z","userPrincipalName":"alice@example.com","status":{"errorCode":0}},
		{"createdDateTime":"not-a-timestamp","userPrincipalName":"mallory@example.com","status":{"errorCode":0}},
		{"createdDateTime":"2026-05-29T11:00:00Z","userPrincipalName":"bob@example.com","status":{"errorCode":0}}
	]}`)

	events, rep, err := Entra(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (the malformed-timestamp entry skipped)", len(events))
	}
	if rep.Records != 3 || rep.Malformed != 1 {
		t.Errorf("rep = %+v, want {Records:3 Malformed:1}", rep)
	}
	for _, e := range events {
		if e.IdentityID == "mallory@example.com" {
			t.Error("the malformed entry must not appear in the parsed events")
		}
	}
}

func TestNormalizeARN(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"arn:aws:sts::123456789012:assumed-role/MyRole/session",
			"arn:aws:iam::123456789012:role/MyRole",
		},
		{
			"arn:aws:iam::123456789012:role/MyRole",
			"arn:aws:iam::123456789012:role/MyRole",
		},
		{
			"arn:aws:iam::123456789012:user/alice",
			"arn:aws:iam::123456789012:user/alice",
		},
	}
	for _, c := range cases {
		got := normalizeARN(c.in)
		if got != c.want {
			t.Errorf("normalizeARN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAWSIAMWithUsage(t *testing.T) {
	iamData := []byte(`{
		"UserDetailList": [],
		"RoleDetailList": [{
			"RoleName": "deploy",
			"Arn": "arn:aws:iam::123:role/deploy",
			"CreateDate": "2025-01-01T00:00:00Z",
			"AttachedManagedPolicies": [
				{"PolicyName": "AmazonS3ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
				{"PolicyName": "AmazonEC2FullAccess",    "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}
			],
			"RolePolicyList": []
		}]
	}`)
	ctData := []byte(`{"Records":[{
		"eventTime":    "2026-05-30T10:00:00Z",
		"eventName":    "GetObject",
		"eventSource":  "s3.amazonaws.com",
		"sourceIPAddress": "10.0.0.1",
		"userIdentity": {
			"arn":  "arn:aws:sts::123:assumed-role/deploy/my-session",
			"type": "AssumedRole"
		}
	}]}`)

	ids, err := AWSSIAMWithUsage(iamData, ctData)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
	perms := make(map[string]bool)
	for _, p := range ids[0].Permissions {
		perms[p.Name] = p.Used
	}
	if !perms["AmazonS3ReadOnlyAccess"] {
		t.Error("AmazonS3ReadOnlyAccess: want Used=true")
	}
	if perms["AmazonEC2FullAccess"] {
		t.Error("AmazonEC2FullAccess: want Used=false")
	}
}

func TestAWSIAMWithUsageAdmin(t *testing.T) {
	iamData := []byte(`{
		"UserDetailList": [],
		"RoleDetailList": [{
			"RoleName": "power-role",
			"Arn": "arn:aws:iam::123:role/power-role",
			"CreateDate": "2025-01-01T00:00:00Z",
			"AttachedManagedPolicies": [
				{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
			],
			"RolePolicyList": []
		}]
	}`)
	// Any CloudTrail activity from this principal should mark AdministratorAccess used.
	ctData := []byte(`{"Records":[{
		"eventTime":   "2026-05-30T10:00:00Z",
		"eventName":   "DescribeInstances",
		"eventSource": "ec2.amazonaws.com",
		"userIdentity": {
			"arn":  "arn:aws:iam::123:role/power-role",
			"type": "IAMUser"
		}
	}]}`)

	ids, err := AWSSIAMWithUsage(iamData, ctData)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || len(ids[0].Permissions) != 1 {
		t.Fatalf("unexpected shape: %+v", ids)
	}
	if !ids[0].Permissions[0].Used {
		t.Error("AdministratorAccess: want Used=true when principal has any CloudTrail activity")
	}
}

func TestCloudTrail(t *testing.T) {
	data := []byte(`{"Records":[
		{"eventTime":"2026-05-29T10:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"1.2.3.4",
		 "userAgent":"Mozilla","userIdentity":{"arn":"arn:aws:iam::1:user/alice","type":"IAMUser"}},
		{"eventTime":"2026-05-29T10:05:00Z","eventName":"AssumeRole","sourceIPAddress":"5.6.7.8",
		 "errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::1:role/deploy","type":"AssumedRole"}}
	]}`)
	events, rep, err := CloudTrail(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Type != model.EventLogin || events[0].IdentityID != "arn:aws:iam::1:user/alice" {
		t.Errorf("event0 = %+v", events[0])
	}
	if events[1].Type != model.EventOther || events[1].Outcome != "FAILURE" {
		t.Errorf("event1 = %+v", events[1])
	}
	if rep.Records != 2 || rep.Malformed != 0 {
		t.Errorf("rep = %+v, want {Records:2 Malformed:0} (no malformed rows in this fixture)", rep)
	}
}

// TestCloudTrailMalformedTimestampSkippedAndCounted is the regression test
// for a silently truncated CloudTrail log: a record whose "eventTime" does
// not parse as RFC3339 was dropped with a bare `continue` and nothing
// surfaced how many were skipped.
func TestCloudTrailMalformedTimestampSkippedAndCounted(t *testing.T) {
	data := []byte(`{"Records":[
		{"eventTime":"2026-05-29T10:00:00Z","eventName":"ConsoleLogin","userIdentity":{"arn":"arn:aws:iam::1:user/alice","type":"IAMUser"}},
		{"eventTime":"not-a-timestamp","eventName":"ConsoleLogin","userIdentity":{"arn":"arn:aws:iam::1:user/mallory","type":"IAMUser"}},
		{"eventTime":"2026-05-29T10:05:00Z","eventName":"AssumeRole","userIdentity":{"arn":"arn:aws:iam::1:role/deploy","type":"AssumedRole"}}
	]}`)

	events, rep, err := CloudTrail(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (the malformed-timestamp record skipped)", len(events))
	}
	if rep.Records != 3 || rep.Malformed != 1 {
		t.Errorf("rep = %+v, want {Records:3 Malformed:1}", rep)
	}
	for _, e := range events {
		if e.IdentityID == "arn:aws:iam::1:user/mallory" {
			t.Error("the malformed record must not appear in the parsed events")
		}
	}
}
