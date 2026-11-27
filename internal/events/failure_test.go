package events

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// A journal that cannot be opened is a startup error naming the path, not a
// sink that silently writes nowhere.
func TestAJournalThatCannotBeOpenedIsRefusedAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no", "such", "dir", "idryx.ndjson")
	s, err := New(path, "run-1", "acme.example")
	if err == nil {
		_ = s.Close()
		t.Fatal("New succeeded on a path whose directory does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name %s", err, path)
	}
}

// A write that fails is returned as an error naming the detector and counted
// as failed, while every other alert in the batch is still attempted.
func TestAFailedWriteIsReturnedAndCounted(t *testing.T) {
	s, _ := open(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := s.Send([]model.Alert{
		alert("stale_nhi", "agent:a", model.SeverityHigh),
		alert("bom_incomplete", "agent:b", model.SeverityMedium),
	})
	if err == nil {
		t.Fatal("writing to a closed journal reported success")
	}
	if !strings.Contains(err.Error(), `"stale_nhi"`) {
		t.Errorf("error = %v, want it to name the first detector that failed", err)
	}
	if _, _, failed := s.Counts(); failed != 2 {
		t.Errorf("failed = %d, want 2: the second alert must still be attempted", failed)
	}
}

// A claimed subject needs the operator's trust domain like any other, and a
// claim whose inner id is not a valid agent URI is not made valid by being
// claimed.
func TestAClaimIsSkippedWithoutADomainOrWithAMalformedInnerID(t *testing.T) {
	noDomain, err := New(filepath.Join(t.TempDir(), "j.ndjson"), "run-1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer noDomain.Close()
	if err := noDomain.Send([]model.Alert{alert("claimed_agent_drift", "claimed:agent://acme.example/planner", model.SeverityHigh)}); err != nil {
		t.Fatal(err)
	}
	if skipped, claimed, _ := noDomain.Counts(); skipped != 1 || claimed != 0 {
		t.Errorf("with no domain: skipped=%d claimed=%d, want 1, 0", skipped, claimed)
	}

	s, _ := open(t)
	if err := s.Send([]model.Alert{alert("claimed_agent_drift", "claimed:agent://ACME EXAMPLE/planner", model.SeverityHigh)}); err != nil {
		t.Fatal(err)
	}
	if skipped, claimed, _ := s.Counts(); skipped != 1 || claimed != 0 {
		t.Errorf("malformed claim: skipped=%d claimed=%d, want 1, 0", skipped, claimed)
	}
}

func TestTheSinkNamesItselfForTheFailureLine(t *testing.T) {
	s, _ := open(t)
	if s.Name() != "agent-event" {
		t.Errorf("Name() = %q, want agent-event", s.Name())
	}
}
