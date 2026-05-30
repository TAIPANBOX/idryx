package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func fixedNow() time.Time { return time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC) }

func withFixedNow(t *testing.T) {
	t.Helper()
	old := now
	now = fixedNow
	t.Cleanup(func() { now = old })
}

func nhiGraph() *graph.Store {
	g := graph.New(nil)
	// stale + admin + owned
	g.AddIdentity(model.Identity{
		ID: "arn:role/old-admin", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Owner: "platform", Created: fixedNow().Add(-365 * 24 * time.Hour),
		LastUsed:    fixedNow().Add(-200 * 24 * time.Hour),
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})
	// fresh + non-admin + no owner (orphaned only)
	g.AddIdentity(model.Identity{
		ID: "arn:role/fresh", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Created: fixedNow().Add(-1 * 24 * time.Hour), LastUsed: fixedNow().Add(-1 * time.Hour),
		Permissions: []model.Permission{{Name: "ReadOnly"}},
	})
	// human — must be ignored by all NHI detectors
	g.AddEvent(model.Event{IdentityID: "alice@x.com", Type: model.EventLogin, Outcome: "SUCCESS", Time: fixedNow()})
	return g
}

func detect(d interface {
	Detect(graph.Reader) []model.Alert
}, g graph.Reader) map[string]model.Alert {
	out := map[string]model.Alert{}
	for _, a := range d.Detect(g) {
		out[a.IdentityID] = a
	}
	return out
}

func TestStaleNHI(t *testing.T) {
	withFixedNow(t)
	got := detect(NewStaleNHI(), nhiGraph())
	if _, ok := got["arn:role/old-admin"]; !ok {
		t.Error("expected old-admin to be stale")
	}
	if _, ok := got["arn:role/fresh"]; ok {
		t.Error("fresh role should not be stale")
	}
	if _, ok := got["alice@x.com"]; ok {
		t.Error("human must not be flagged by stale_nhi")
	}
	if got["arn:role/old-admin"].Severity != model.SeverityHigh {
		t.Error("stale admin NHI should be high severity")
	}
}

func TestOverPrivilegedNHI(t *testing.T) {
	withFixedNow(t)
	got := detect(NewOverPrivilegedNHI(), nhiGraph())
	if len(got) != 1 || got["arn:role/old-admin"].Severity != model.SeverityHigh {
		t.Errorf("expected only old-admin flagged high, got %v", got)
	}
}

func TestOrphanedNHI(t *testing.T) {
	withFixedNow(t)
	got := detect(NewOrphanedNHI(), nhiGraph())
	if _, ok := got["arn:role/fresh"]; !ok {
		t.Error("fresh (no owner) should be orphaned")
	}
	if _, ok := got["arn:role/old-admin"]; ok {
		t.Error("owned role should not be orphaned")
	}
}
