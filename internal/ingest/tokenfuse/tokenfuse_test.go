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

// TestParseDerivesSourceFromEnvelope is the regression test for the
// source-attribution bug (agent-passport SPEC §6.3): Parse must take every
// identity's and event's Source from the envelope's own `source` field,
// never hardcode "tokenfuse" regardless of which producer actually wrote
// the line. A wardryx-sourced envelope must yield Source "wardryx", not
// "tokenfuse".
func TestParseDerivesSourceFromEnvelope(t *testing.T) {
	line := []byte(`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-10T09:00:00Z","source":"wardryx","type":"policy_deny","severity":"high","agent_id":"agent://acme-bank.example/support/tier1-bot","on_behalf_of":["user://acme-bank.example/j.doe"]}` + "\n")

	identities, events, rep := Parse(line)
	if rep.Malformed != 0 {
		t.Fatalf("Malformed = %d, want 0: %+v", rep.Malformed, rep)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %d, want 2 (agent + human)", len(identities))
	}
	for _, id := range identities {
		if id.Source != "wardryx" {
			t.Errorf("identity %s Source = %q, want %q (must come from the envelope, never hardcoded)", id.ID, id.Source, "wardryx")
		}
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Source != "wardryx" {
		t.Errorf("event Source = %q, want %q (must come from the envelope, never hardcoded)", events[0].Source, "wardryx")
	}
}

// TestParseBusFixtures proves each new agent-event-bus producer (Wardryx,
// Mockryx, Verdryx) parses through the same connector as TokenFuse, using
// the on-disk fixtures under testdata/{wardryx,mockryx,verdryx}: every
// identity and event they produce must be attributed to that producer's
// own source (never "tokenfuse"), and the on_behalf_of chain must still
// populate the identity graph the same way it does for TokenFuse.
func TestParseBusFixtures(t *testing.T) {
	const humanID = "user://acme-bank.example/j.doe"
	tests := []struct {
		name           string
		file           string
		wantIdentities int
		wantEvents     int
		wantUnknown    int // len(rep.UnknownTypes): distinct unknown type strings
		wantAgentIDs   []string
	}{
		{
			name:           "wardryx",
			file:           "testdata/wardryx/events.ndjson",
			wantIdentities: 3, // tier1-bot, orchestrator, human
			wantEvents:     3,
			wantUnknown:    3, // policy_deny, approval_requested, approval_granted
			wantAgentIDs: []string{
				"agent://acme-bank.example/support/tier1-bot",
				"agent://acme-bank.example/support/orchestrator",
			},
		},
		{
			name:           "mockryx",
			file:           "testdata/mockryx/events.ndjson",
			wantIdentities: 2, // tier1-bot, human
			wantEvents:     2,
			wantUnknown:    2, // sim_finding, blast_radius_measured
			wantAgentIDs: []string{
				"agent://acme-bank.example/support/tier1-bot",
			},
		},
		{
			name:           "verdryx",
			file:           "testdata/verdryx/events.ndjson",
			wantIdentities: 3, // tier1-bot, orchestrator, human
			wantEvents:     2,
			wantUnknown:    1, // both lines share the type "quality_drift"
			wantAgentIDs: []string{
				"agent://acme-bank.example/support/tier1-bot",
				"agent://acme-bank.example/support/orchestrator",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			identities, events, rep := Parse(data)

			if rep.Malformed != 0 {
				t.Errorf("Malformed = %d, want 0", rep.Malformed)
			}
			if len(rep.UnknownTypes) != tt.wantUnknown {
				t.Errorf("len(UnknownTypes) = %d, want %d: %v", len(rep.UnknownTypes), tt.wantUnknown, rep.UnknownTypes)
			}
			if len(identities) != tt.wantIdentities {
				t.Fatalf("identities = %d, want %d: %+v", len(identities), tt.wantIdentities, identities)
			}
			if len(events) != tt.wantEvents {
				t.Fatalf("events = %d, want %d", len(events), tt.wantEvents)
			}

			byID := map[string]model.Identity{}
			for _, id := range identities {
				byID[id.ID] = id
				// Every identity in this single-producer file must carry
				// that producer's own source, never a hardcoded "tokenfuse".
				if id.Source != tt.name {
					t.Errorf("identity %s Source = %q, want %q", id.ID, id.Source, tt.name)
				}
			}
			for _, e := range events {
				if e.Source != tt.name {
					t.Errorf("event %s/%s Source = %q, want %q", e.IdentityID, e.Type, e.Source, tt.name)
				}
			}

			human, ok := byID[humanID]
			if !ok || human.Type != model.IdentityHuman {
				t.Errorf("expected human identity %s, got %+v", humanID, byID)
			}
			for _, agentID := range tt.wantAgentIDs {
				agent, ok := byID[agentID]
				if !ok {
					t.Errorf("expected agent identity %s in %+v", agentID, byID)
					continue
				}
				if agent.Type != model.IdentityAgent {
					t.Errorf("%s Type = %q, want agent", agentID, agent.Type)
				}
				if len(agent.OnBehalfOf) != 1 || agent.OnBehalfOf[0] != humanID {
					t.Errorf("%s OnBehalfOf = %v, want [%s]", agentID, agent.OnBehalfOf, humanID)
				}
			}
		})
	}
}
