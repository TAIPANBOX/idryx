package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestSharedCredential(t *testing.T) {
	withFixedNow(t)

	g := graph.New(nil)

	// NHI used across 3 distinct IPs
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::123456789012:role/shared-svc",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
	})
	g.AddEvent(model.Event{IdentityID: "arn:aws:iam::123456789012:role/shared-svc", IP: "10.0.0.1", Country: "US", Device: "Lambda", Outcome: "SUCCESS", Time: fixedNow()})
	g.AddEvent(model.Event{IdentityID: "arn:aws:iam::123456789012:role/shared-svc", IP: "192.168.1.100", Country: "US", Device: "Lambda", Outcome: "SUCCESS", Time: fixedNow()})
	g.AddEvent(model.Event{IdentityID: "arn:aws:iam::123456789012:role/shared-svc", IP: "8.8.8.8", Country: "UA", Device: "DeveloperConsole", Outcome: "SUCCESS", Time: fixedNow()})

	// NHI used from a single origin
	g.AddIdentity(model.Identity{
		ID:     "arn:aws:iam::123456789012:role/single-svc",
		Type:   model.IdentityServiceAccount,
		Source: "aws_iam",
	})
	g.AddEvent(model.Event{IdentityID: "arn:aws:iam::123456789012:role/single-svc", IP: "10.0.0.1", Country: "US", Device: "Lambda", Outcome: "SUCCESS", Time: fixedNow()})
	g.AddEvent(model.Event{IdentityID: "arn:aws:iam::123456789012:role/single-svc", IP: "10.0.0.1", Country: "US", Device: "Lambda", Outcome: "SUCCESS", Time: fixedNow().Add(time.Hour)})

	// Human used across 3 distinct IPs (should be ignored)
	g.AddIdentity(model.Identity{
		ID:   "human-user@example.com",
		Type: model.IdentityHuman,
	})
	g.AddEvent(model.Event{IdentityID: "human-user@example.com", IP: "1.1.1.1", Country: "DE", Device: "Safari", Outcome: "SUCCESS", Time: fixedNow()})
	g.AddEvent(model.Event{IdentityID: "human-user@example.com", IP: "2.2.2.2", Country: "FR", Device: "Chrome", Outcome: "SUCCESS", Time: fixedNow()})
	g.AddEvent(model.Event{IdentityID: "human-user@example.com", IP: "3.3.3.3", Country: "UK", Device: "Firefox", Outcome: "SUCCESS", Time: fixedNow()})

	got := detect(NewSharedCredential(), g)

	if a, ok := got["arn:aws:iam::123456789012:role/shared-svc"]; !ok {
		t.Error("expected shared-svc to be flagged for shared credentials")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", a.Severity)
	}

	if _, ok := got["arn:aws:iam::123456789012:role/single-svc"]; ok {
		t.Error("single-svc role should not be flagged")
	}

	if _, ok := got["human-user@example.com"]; ok {
		t.Error("human identity should not be flagged by shared_credential detector")
	}
}
