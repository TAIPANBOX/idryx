package tokenfuse

import (
	"os"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestParseFixture exercises the full fixture: agent creation (including a
// repeat-agent line that must not re-create the identity), chain population
// (both a one-hop and a two-hop flattened chain), all eight v0.1 event
// types, one unknown type, and one malformed line.
func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/events.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	identities, events, rep := Parse(data)

	if rep.Lines != 11 {
		t.Errorf("Lines = %d, want 11", rep.Lines)
	}
	if rep.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", rep.Malformed)
	}
	if len(rep.UnknownTypes) != 1 || rep.UnknownTypes["model_swap_detected"] != 1 {
		t.Errorf("UnknownTypes = %v, want {model_swap_detected:1}", rep.UnknownTypes)
	}
	if len(events) != 10 {
		t.Fatalf("events = %d, want 10 (11 lines - 1 malformed)", len(events))
	}

	if len(identities) != 4 {
		t.Fatalf("identities = %d, want 4: %+v", len(identities), identities)
	}
	byID := map[string]model.Identity{}
	for _, id := range identities {
		byID[id.ID] = id
	}

	tier1 := byID["agent://acme-bank.example/support/tier1-bot"]
	if tier1.Type != model.IdentityAgent || tier1.Source != "tokenfuse" {
		t.Errorf("tier1-bot = %+v", tier1)
	}
	if len(tier1.OnBehalfOf) != 1 || tier1.OnBehalfOf[0] != "user://acme-bank.example/j.doe" {
		t.Errorf("tier1-bot chain = %v, want [user://acme-bank.example/j.doe]", tier1.OnBehalfOf)
	}

	human := byID["user://acme-bank.example/j.doe"]
	if human.Type != model.IdentityHuman || human.Source != "tokenfuse" {
		t.Errorf("human principal = %+v, want IdentityHuman/tokenfuse", human)
	}

	orch := byID["agent://acme-bank.example/support/orchestrator"]
	if orch.Type != model.IdentityAgent {
		t.Errorf("orchestrator = %+v", orch)
	}

	sub := byID["agent://acme-bank.example/support/sub-agent"]
	if sub.Type != model.IdentityAgent {
		t.Errorf("sub-agent = %+v", sub)
	}
	wantChain := []string{"user://acme-bank.example/j.doe", "agent://acme-bank.example/support/orchestrator"}
	if len(sub.OnBehalfOf) != len(wantChain) {
		t.Fatalf("sub-agent chain = %v, want %v", sub.OnBehalfOf, wantChain)
	}
	for i := range wantChain {
		if sub.OnBehalfOf[i] != wantChain[i] {
			t.Errorf("sub-agent chain[%d] = %q, want %q", i, sub.OnBehalfOf[i], wantChain[i])
		}
	}

	// All eight v0.1 registry types (SPEC §6.2) must be present, mapped to
	// their named model.EventType constants.
	wantTypes := map[model.EventType]bool{
		model.EventBudgetExhausted: false,
		model.EventSustainedLoop:   false,
		model.EventSpendSpike:      false,
		model.EventFanoutExplosion: false,
		model.EventBreakerTripped:  false,
		model.EventDLPBlock:        false,
		model.EventTaintBlock:      false,
		model.EventMCPDrift:        false,
	}
	sawUnknown := false
	var sawBudgetExhaustedSeverity string
	for _, e := range events {
		if _, ok := wantTypes[e.Type]; ok {
			wantTypes[e.Type] = true
		}
		if e.Type == model.EventType("model_swap_detected") {
			sawUnknown = true
		}
		if e.IdentityID == "agent://acme-bank.example/support/tier1-bot" && e.Type == model.EventBudgetExhausted {
			sawBudgetExhaustedSeverity = e.Severity
		}
		// The envelope has no SUCCESS/FAILURE concept; Outcome must stay
		// empty — severity lives in its own dedicated field.
		if e.Outcome != "" {
			t.Errorf("event %s/%s Outcome = %q, want empty (severity must not overload Outcome)", e.IdentityID, e.Type, e.Outcome)
		}
	}
	for typ, seen := range wantTypes {
		if !seen {
			t.Errorf("event type %q from the v0.1 registry was not ingested", typ)
		}
	}
	if !sawUnknown {
		t.Error("event type outside the v0.1 registry must still be ingested generically, never dropped")
	}
	if sawBudgetExhaustedSeverity != "critical" {
		t.Errorf("budget_exhausted Severity = %q, want critical", sawBudgetExhaustedSeverity)
	}
}

// TestParseMalformedNeverErrors asserts the core tolerance contract: bad
// JSON, missing required fields, and an unparseable timestamp are each
// counted and skipped, never causing Parse to panic or otherwise abort.
func TestParseMalformedNeverErrors(t *testing.T) {
	data := []byte(
		"not json at all\n" +
			`{"schema":""}` + "\n" +
			`{"schema":"taipanbox.dev/agent-event/v0.1","ts":"not-a-time","source":"tokenfuse","type":"budget_exhausted","agent_id":"agent://x/y"}` + "\n" +
			"\n", // blank line must be skipped without counting as a line at all
	)
	identities, events, rep := Parse(data)
	if len(identities) != 0 || len(events) != 0 {
		t.Fatalf("expected no identities/events from entirely malformed input, got %d/%d", len(identities), len(events))
	}
	if rep.Lines != 3 {
		t.Errorf("Lines = %d, want 3 (blank line excluded)", rep.Lines)
	}
	if rep.Malformed != 3 {
		t.Errorf("Malformed = %d, want 3", rep.Malformed)
	}
}

func TestLoadGlob(t *testing.T) {
	identities, events, rep, err := Load("testdata/*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 4 {
		t.Errorf("identities = %d, want 4", len(identities))
	}
	if len(events) != 10 {
		t.Errorf("events = %d, want 10", len(events))
	}
	if rep.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", rep.Malformed)
	}
}

func TestLoadSingleFile(t *testing.T) {
	identities, events, _, err := Load("testdata/events.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 4 || len(events) != 10 {
		t.Errorf("identities/events = %d/%d, want 4/10", len(identities), len(events))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, _, _, err := Load("testdata/does-not-exist.ndjson")
	if err == nil {
		t.Fatal("expected an error for a missing, non-glob file")
	}
}
