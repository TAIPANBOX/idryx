package events

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func open(t *testing.T) (*Sink, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "idryx.ndjson")
	s, err := New(path, "run-scan-1", "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("a configured path must produce a sink")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func alert(detector, identity string, sev model.Severity) model.Alert {
	return model.Alert{
		Detector:   detector,
		IdentityID: identity,
		Severity:   sev,
		Time:       time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC),
		Summary:    "the identity j.doe@corp.example exceeded its declared scope",
	}
}

// The decision this package was built around: one type, the detector name in
// data. `@yurii 2026-08-10`, "перший, один тип".
func TestEveryFindingIsOneTypeAndTheDetectorTravelsInData(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("shadow_mcp", "agent:tier1-bot", model.SeverityHigh),
		alert("undeclared_llm", "agent:analyst", model.SeverityMedium),
	}); err != nil {
		t.Fatal(err)
	}

	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want two events, got %d", len(evs))
	}
	for _, e := range evs {
		if e.Type != TypeIdentityFinding {
			t.Errorf("type = %q, want the one type this product emits", e.Type)
		}
		if e.Source != Source {
			t.Errorf("source = %q", e.Source)
		}
	}
	if evs[0].Data["detector"] != "shadow_mcp" || evs[1].Data["detector"] != "undeclared_llm" {
		t.Errorf("the detector must travel in data, got %v and %v", evs[0].Data, evs[1].Data)
	}
	if evs[0].Severity != "high" || evs[1].Severity != "medium" {
		t.Errorf("severities = %q, %q", evs[0].Severity, evs[1].Severity)
	}
}

// SPEC 6.1. idryx inventories service accounts, machine identities and people
// as well as agents, and an observation with no agent subject cannot travel in
// this envelope at all. A fabricated subject would make every downstream count
// wrong and put a name on an alert that did not do the thing.
func TestAFindingAboutANonAgentIsSkippedAndCountedNeverInvented(t *testing.T) {
	s, path := open(t)
	notAgents := []string{
		"j.doe@corp.example",
		"user://acme.example/j.doe",
		"arn:aws:iam::123456789012:role/deploy",
		"",
		"agent:",           // the prefix with no name
		"agent:Ops-Helper", // uppercase is outside the envelope's grammar
	}
	var alerts []model.Alert
	for _, id := range notAgents {
		alerts = append(alerts, alert("over_privileged_nhi", id, model.SeverityHigh))
	}
	if err := s.Send(alerts); err != nil {
		t.Fatal(err)
	}

	skipped, _, failed := s.Counts()
	if skipped != len(notAgents) {
		t.Errorf("skipped = %d, want %d: a skip nobody counts is a skip nobody knows about",
			skipped, len(notAgents))
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}
	if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
		t.Errorf("nothing may be written without an agent subject, got:\n%s", raw)
	}
}

// The Summary names people and the IdentityID of a human identity IS a person.
// Neither is written: the subject is already the typed `agent_id`, and the
// event is the part designed to be kept.
func TestNoProseAndNoHumanIdentityReachesTheEvent(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("behavior_anomaly", "agent:tier1-bot", model.SeverityHigh),
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, secret := range []string{"j.doe@corp.example", "exceeded its declared scope", "summary"} {
		if strings.Contains(line, secret) {
			t.Errorf("the event carries %q, which is prose or personal data:\n%s", secret, line)
		}
	}
	if !strings.Contains(line, "behavior_anomaly") {
		t.Error("the detector must be there: it is the whole vocabulary a consumer routes on")
	}
}

// No severity threshold of its own. Slack and OTLP filter because they page a
// person; a record filtered by severity answers "what happened" with "the parts
// somebody thought were interesting".
func TestTheRecordIsNotFilteredBySeverity(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("bom_incomplete", "agent:a", model.SeverityInfo),
		alert("stale_nhi", "agent:b", model.SeverityLow),
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("a low-severity finding is still a finding, got %d events", len(evs))
	}
}

// Not wanting a bus destination is a configuration, and a nil sink is safe to
// call, because the caller adds it to a list rather than branching on it.
func TestAnUnconfiguredSinkIsNilAndSafeToUse(t *testing.T) {
	s, err := New("", "run-1", "acme.example")
	if err != nil {
		t.Fatalf("an empty path is not a fault: %v", err)
	}
	if s != nil {
		t.Fatal("an empty path must produce no sink")
	}
	if err := s.Send([]model.Alert{alert("shadow_ai", "agent:a", model.SeverityHigh)}); err != nil {
		t.Errorf("a nil sink must accept a send: %v", err)
	}
	if skipped, claimed, failed := s.Counts(); skipped != 0 || claimed != 0 || failed != 0 {
		t.Errorf("a nil sink counts nothing, got %d/%d/%d", skipped, claimed, failed)
	}
	if err := s.Close(); err != nil {
		t.Errorf("a nil sink must close: %v", err)
	}
}

// An unknown band must not make a finding disappear.
func TestAnUnknownSeverityBecomesMediumRatherThanNothing(t *testing.T) {
	if got := severityWire(model.Severity(99)); got != "medium" {
		t.Errorf("severityWire(unknown) = %q, want medium", got)
	}
	for sev, want := range map[model.Severity]string{
		model.SeverityInfo:     "info",
		model.SeverityLow:      "low",
		model.SeverityMedium:   "medium",
		model.SeverityHigh:     "high",
		model.SeverityCritical: "critical",
	} {
		if got := severityWire(sev); got != want {
			t.Errorf("severityWire(%v) = %q, want %q", sev, got, want)
		}
	}
}

// Two namespaces, and only the operator can bridge them.
//
// idryx inventories `agent:ops-helper`; the envelope wants
// `agent://<trust-domain>/<name>`. The NAME comes from the inventory and the
// DOMAIN can only come from the operator. trailryx refuses on exactly this
// comparison at the other end, so inventing a domain here would be
// manufacturing the case its invariant 35 exists to catch.
func TestWithNoTrustDomainNothingIsWrittenAndTheCountSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idryx.ndjson")
	s, err := New(path, "run-1", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Send([]model.Alert{
		alert("shadow_mcp", "agent:tier1-bot", model.SeverityHigh),
	}); err != nil {
		t.Fatal(err)
	}
	if skipped, _, _ := s.Counts(); skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
		t.Errorf("nothing may be written without a configured domain, got:\n%s", raw)
	}
}

// An identity that ALREADY is a canonical agent URI must travel as itself.
//
// This is the namespace the bus connector produces: every event idryx ingests
// from tokenfuse, wardryx, mockryx, verdryx or scopyx creates an identity whose
// id is the envelope's own `agent_id`, i.e. `agent://<domain>/<name>`. Those
// ids also begin with "agent:", so cutting that prefix and prepending the
// operator's domain builds a second scheme onto a string that already had one.
//
// Measured before this test existed, on a real run against
// testdata/tokenfuse.ndjson with IDRYX_TRUST_DOMAIN=acme.example: the journal
// received `agent://acme.example///acme-bank.example/support/tier1-bot`, and
// passport.ValidateAgentURI accepts that shape, so it was written rather than
// refused. The finding was not lost; it was published about an agent that does
// not exist.
func TestAnIdentityThatIsAlreadyACanonicalURITravelsAsItself(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("bom_incomplete", "agent://acme.example/planner", model.SeverityMedium),
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want one event, got %d", len(evs))
	}
	if evs[0].AgentID != "agent://acme.example/planner" {
		t.Errorf("agent_id = %q, want the identity unchanged: it was already canonical", evs[0].AgentID)
	}
}

// The operator's own trust domain is never stamped onto an identity that
// carried a different one.
//
// Deliberately weaker than naming one expected string, because it holds under
// both answers to "what should a foreign domain do": pass the true subject
// through, or skip and count it. What it refuses is the third answer, the one
// that shipped: re-stamping another organisation's agent as ours. trustedID's
// own comment cites trailryx invariant 35 for why, and the run that produced
// `agent://acme.example///acme-bank.example/support/tier1-bot` was doing
// exactly what that comment says must never happen.
func TestAForeignTrustDomainIsNeverRestampedAsTheOperatorsOwn(t *testing.T) {
	s, path := open(t) // the operator's domain is acme.example
	if err := s.Send([]model.Alert{
		alert("orphaned_nhi", "agent://acme-bank.example/support/tier1-bot", model.SeverityLow),
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if strings.HasPrefix(e.AgentID, "agent://acme.example/") {
			t.Errorf("agent_id = %q: an agent of acme-bank.example was published under the operator's own domain", e.AgentID)
		}
	}
}

// A self-declared subject is held back, and counted apart from the identities
// that are simply not agents.
//
// Both halves matter and they fail differently. Writing it would deliver a
// claim as a fact to every conforming consumer, which SPEC 3.3 forbids and no
// `data` key can undo, since 6.1 obliges a consumer to ignore keys it does not
// know. Counting it as "no agent subject" would file a gap under a property:
// a person will never have a subject and this agent might, once the envelope
// can say a subject was asserted rather than established.
func TestAClaimedSubjectIsHeldBackAndCountedApartFromANonAgent(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("claimed_agent_drift", "claimed:agent://acme.example/planner", model.SeverityHigh),
		alert("unmanaged_egress", "proc:python3@cg8471", model.SeverityMedium),
		alert("bom_incomplete", "agent:ops-helper", model.SeverityMedium),
	}); err != nil {
		t.Fatal(err)
	}

	skipped, claimed, failed := s.Counts()
	if claimed != 1 {
		t.Errorf("claimed = %d, want 1: a self-declared subject is its own story, not a missing one", claimed)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the proc: identity, which is not an agent under any envelope)", skipped)
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0", failed)
	}

	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want exactly the one established subject on the bus, got %d", len(evs))
	}
	if evs[0].AgentID != "agent://acme.example/ops-helper" {
		t.Errorf("agent_id = %q, want the established identity", evs[0].AgentID)
	}
	if strings.Contains(evs[0].AgentID, "planner") {
		t.Error("a claim a process made about itself reached the bus as an established subject")
	}
}

// The subject is BUILT from the inventory name and the configured domain, and
// then validated, so a name idryx accepted but the envelope's grammar does not
// is refused here rather than written.
func TestTheSubjectIsBuiltFromTheInventoryNameAndTheOperatorsDomain(t *testing.T) {
	s, path := open(t)
	if err := s.Send([]model.Alert{
		alert("attestation_missing", "agent:ops-helper", model.SeverityHigh),
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want one event, got %d", len(evs))
	}
	if evs[0].AgentID != "agent://acme.example/ops-helper" {
		t.Errorf("agent_id = %q, want the inventory name under the operator's domain", evs[0].AgentID)
	}
}
