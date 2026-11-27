package detectors

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestPrivilegeEscalationReadsTheActionsAGrantAllows is the path every shipped
// connector takes: the grant is named after a policy, and the escalation
// action is inside it. One alert per grant, on the first matching action.
func TestPrivilegeEscalationReadsTheActionsAGrantAllows(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "arn:aws:iam::1:role/ci", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Permissions: []model.Permission{
			{Name: "DeployPolicy", Actions: []string{"s3:putobject", "IAM:PassRole", "iam:createaccesskey"}},
			{Name: "ReadOnly", Actions: []string{"s3:getobject", "ec2:describeinstances"}},
		},
	})
	g.AddIdentity(model.Identity{ID: "bob@x.com", Permissions: []model.Permission{{Name: "Human", Actions: []string{"iam:passrole"}}}})

	alerts := NewPrivilegeEscalation().Detect(g)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want exactly one for DeployPolicy: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.IdentityID != "arn:aws:iam::1:role/ci" || a.Severity != model.SeverityHigh {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Summary, `"IAM:PassRole" via grant "DeployPolicy"`) {
		t.Errorf("summary = %q, want it to name the action as granted and the grant", a.Summary)
	}
}

func TestStaleNHIFallsBackToCreatedAndSkipsAnIdentityWithNoTimeline(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{ID: "svc:old", Type: model.IdentityServiceAccount, Created: fixedNow().Add(-200 * 24 * time.Hour)})
	g.AddIdentity(model.Identity{ID: "svc:unknown", Type: model.IdentityServiceAccount})
	g.AddIdentity(model.Identity{ID: "svc:fresh", Type: model.IdentityServiceAccount, Created: fixedNow().Add(-89 * 24 * time.Hour)})

	alerts := NewStaleNHI().Detect(g)
	if len(alerts) != 1 || alerts[0].IdentityID != "svc:old" {
		t.Fatalf("alerts = %+v, want only svc:old", alerts)
	}
	if alerts[0].Summary != "NHI stale: created 200d ago" {
		t.Errorf("summary = %q, want the created date named as the reference", alerts[0].Summary)
	}
}

func TestIsPublicDestination(t *testing.T) {
	cases := map[string]bool{
		"api.example.com":          true,
		"8.8.8.8":                  true,
		"2001:4860:4860::8888":     true,
		"db.internal":              false,
		"printer.local":            false,
		"host.localdomain":         false,
		"svc.ns.svc.cluster.local": false,
		"localhost":                false,
		"":                         false,
		"127.0.0.1":                false,
		"169.254.169.254":          false,
		"10.1.2.3":                 false,
		"::ffff:10.0.0.1":          false,
		"fd00::1":                  false,
		"100.64.0.1":               false,
		"::ffff:100.64.0.1":        false,
		"100.128.0.1":              true,
		"0.1.2.3":                  false,
	}
	for host, want := range cases {
		if got := isPublicDestination(host); got != want {
			t.Errorf("isPublicDestination(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestMatchLLMHostReturnsTheProviderIDNotTheDisplayName(t *testing.T) {
	if id, ok := MatchLLMHost("api.anthropic.com"); !ok || id != "anthropic" {
		t.Errorf("MatchLLMHost(api.anthropic.com) = %q, %v; want anthropic, true", id, ok)
	}
	if id, ok := MatchLLMHost("generativelanguage.googleapis.com"); !ok || id != "google" {
		t.Errorf("MatchLLMHost(gemini) = %q, %v; want the id google, not the display name", id, ok)
	}
	if id, ok := MatchLLMHost("example.com"); ok || id != "" {
		t.Errorf("MatchLLMHost(example.com) = %q, %v; want no match", id, ok)
	}
}

func TestMeanAndCVNeverDividesByZero(t *testing.T) {
	if mean, cv := meanAndCV(nil); mean != 0 || cv != 1 {
		t.Errorf("meanAndCV(nil) = %v, %v; want 0, 1", mean, cv)
	}
	if mean, cv := meanAndCV([]float64{0, 0, 0}); mean != 0 || cv != 1 {
		t.Errorf("meanAndCV(zeros) = %v, %v; want 0, 1 (no threshold accepts it)", mean, cv)
	}
	if mean, cv := meanAndCV([]float64{60, 60, 60}); mean != 60 || cv != 0 {
		t.Errorf("meanAndCV(steady) = %v, %v; want 60, 0", mean, cv)
	}
	if _, cv := meanAndCV([]float64{50, 70}); math.Abs(cv-10.0/60.0) > 1e-9 {
		t.Errorf("cv = %v, want %v", cv, 10.0/60.0)
	}
}

// TestBeaconingIgnoresNonEgressEventsAndEmptyDestinations: only egress
// events with a destination form a cadence; logins at a steady rhythm are
// a person's habits, not a beacon.
func TestBeaconingIgnoresNonEgressEventsAndEmptyDestinations(t *testing.T) {
	withFixedNow(t)
	g := graph.New(nil)
	start := fixedNow().Add(-24 * time.Hour)
	for i := 0; i < 40; i++ {
		ts := start.Add(time.Duration(i) * time.Minute)
		g.AddEvent(model.Event{IdentityID: "proc:x", Type: model.EventLogin, Time: ts, Resource: "c2.example.net"})
		g.AddEvent(model.Event{IdentityID: "proc:x", Type: model.EventEgress, Time: ts})
	}
	if alerts := NewBeaconing().Detect(g); len(alerts) != 0 {
		t.Errorf("got %d beaconing alert(s) from non-egress or destination-less events: %+v", len(alerts), alerts)
	}
}
