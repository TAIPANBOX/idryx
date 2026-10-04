package tokenfuse

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/ingest/stream"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestParseFixture exercises the full fixture: agent creation (including a
// repeat-agent line that must not re-create the identity), chain population
// (both a one-hop and a two-hop flattened chain), all eight v0.1 event
// types, one unknown type, and one malformed line.
func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/tokenfuse.ndjson")
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
	identities, events, _, err := Load("testdata/tokenfuse.ndjson")
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
			file:           "testdata/wardryx/wardryx.ndjson",
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
			file:           "testdata/mockryx/mockryx.ndjson",
			wantIdentities: 2, // tier1-bot, human
			wantEvents:     2,
			wantUnknown:    2, // sim_finding, blast_radius_measured
			wantAgentIDs: []string{
				"agent://acme-bank.example/support/tier1-bot",
			},
		},
		{
			name:           "verdryx",
			file:           "testdata/verdryx/verdryx.ndjson",
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

// A claimed subject arriving over the bus is the same fact as one the sensor
// read off a process, and must become the same kind of node.
//
// agent-passport SPEC 3.3 gave `claimed:agent://...` a wire form on 2026-08-10,
// so this connector started meeting the string. It typed every `agent_id` as an
// established agent without looking at it, which made the SAME id two different
// things depending on which door it came through: the sensor creates it through
// AddEvent, where the type stays unset, and the bus created it as a governed
// agent.
//
// The consequence was not academic. `bom_incomplete` selects on IsAgent(), so
// feeding idryx its own journal back reported a missing owner, runtime and
// attestation for a name nobody ever issued, and `orphaned_nhi` reported that
// nobody owns it. An Agent-BOM cannot be incomplete for something that was never
// issued, and a self-declaration has no owner to be missing.
func TestAClaimedSubjectFromTheBusIsNotTypedAsAnEstablishedAgent(t *testing.T) {
	const stream = `{"schema":"taipanbox.dev/agent-event/v0.3","ts":"2026-08-10T09:30:00.000Z","source":"idryx","type":"identity_finding","agent_id":"claimed:agent://acme.example/planner","severity":"high","data":{"detector":"unrouted_egress"}}
{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-10T09:31:00.000Z","source":"idryx","type":"identity_finding","agent_id":"agent://acme.example/auditor","severity":"medium","data":{"detector":"bom_incomplete"}}`

	ids, _, rep := Parse([]byte(stream))
	if rep.Malformed != 0 {
		t.Fatalf("malformed = %d, want 0", rep.Malformed)
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	claimed, ok := byID["claimed:agent://acme.example/planner"]
	if !ok {
		t.Fatalf("the claimed subject did not become an identity at all: %v", byID)
	}
	if claimed.Type == model.IdentityAgent {
		t.Error("a claim was typed as an established agent; the posture detectors would then " +
			"report an incomplete Agent-BOM for a name the organisation never issued")
	}

	// And the established one is untouched: this is a branch, not a new default.
	established, ok := byID["agent://acme.example/auditor"]
	if !ok {
		t.Fatalf("the established subject is missing: %v", byID)
	}
	if established.Type != model.IdentityAgent {
		t.Errorf("an established subject came out as %q, want an agent", established.Type)
	}
}

func envLine(source, agent string) string {
	return `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-10-04T10:00:00Z","source":"` + source +
		`","type":"spend_spike","severity":"high","agent_id":"agent://acme.example/` + agent + `"}` + "\n"
}

func writeStream(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A line whose claimed source the file may not carry creates no identity and
// no event, and is counted beside Malformed with the pair that explains it.
func TestLoadRefusesAForeignSourceAndCountsIt(t *testing.T) {
	p := writeStream(t, "tokenfuse.ndjson",
		envLine("tokenfuse", "legit")+envLine("wardryx", "forged")+envLine("wardryx", "forged-too")+envLine("engram", "other"))

	ids, events, rep, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0].ID != "agent://acme.example/legit" || len(events) != 1 {
		t.Fatalf("only the legitimate line may reach the graph: %+v / %+v", ids, events)
	}
	if rep.ForeignSource != 3 || rep.Malformed != 0 || rep.Lines != 4 {
		t.Fatalf("ForeignSource = %d, Malformed = %d, Lines = %d, want 3, 0, 4", rep.ForeignSource, rep.Malformed, rep.Lines)
	}
	if len(rep.Foreign) != 2 || rep.Foreign[0].Claimed != "engram" || rep.Foreign[0].Count != 1 ||
		rep.Foreign[1].Claimed != "wardryx" || rep.Foreign[1].Count != 2 {
		t.Fatalf("pairs not grouped by (file, claim) in a stable order: %+v", rep.Foreign)
	}
	if f := rep.Foreign[1]; f.File != p || f.Stem != "tokenfuse" || len(f.Allowed) != 1 || f.Allowed[0] != "tokenfuse" {
		t.Fatalf("a pair must name the file and what it may carry: %+v", f)
	}
}

// Parse is handed bytes and no file, so it has nothing to check a claim
// against and applies no rule; the door for a file is Load. Pinned so a caller
// that reads a file and calls Parse is a visible choice.
func TestParseWithoutAFileAppliesNoStreamRule(t *testing.T) {
	ids, events, rep := Parse([]byte(envLine("wardryx", "a") + envLine("tokenfuse", "b")))
	if len(ids) != 2 || len(events) != 2 || rep.ForeignSource != 0 {
		t.Fatalf("Parse refused something it has no file to refuse by: %d ids, %d events, %d foreign", len(ids), len(events), rep.ForeignSource)
	}
}

// An operator's declaration reaches the rule through LoadWith.
func TestLoadWithADeclarationWidensWhatAFileMayCarry(t *testing.T) {
	p := writeStream(t, "events.ndjson", envLine("tokenfuse", "t")+envLine("wardryx", "w"))

	if ids, _, rep, _ := Load(p); len(ids) != 0 || rep.ForeignSource != 2 {
		t.Fatalf("an undeclared events.ndjson must refuse other planes' names: %d ids, %d foreign", len(ids), rep.ForeignSource)
	}
	pol := stream.Default().Extend(map[string][]string{"events": {"tokenfuse", "wardryx"}})
	ids, _, rep, err := LoadWith(p, pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || rep.ForeignSource != 0 || rep.UnknownStream != 0 {
		t.Fatalf("a declared file reads whole and reports nothing: %d ids, %d foreign, %d unknown", len(ids), rep.ForeignSource, rep.UnknownStream)
	}
}

// A stream nothing declares is ingested when its lines claim its own name,
// counted, and named; a line claiming any other name is refused.
func TestAnUnknownStreamIsIngestedAndCountedAndAnotherNameIsRefused(t *testing.T) {
	p := writeStream(t, "newplane.ndjson", envLine("newplane", "n1")+envLine("newplane", "n2")+envLine("tokenfuse", "forged"))
	ids, _, rep, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || rep.UnknownStream != 2 || rep.ForeignSource != 1 {
		t.Fatalf("%d ids, UnknownStream = %d, ForeignSource = %d, want 2, 2, 1", len(ids), rep.UnknownStream, rep.ForeignSource)
	}
	if len(rep.Unknown) != 1 || rep.Unknown[0].File != p || rep.Unknown[0].Stem != "newplane" || rep.Unknown[0].Count != 2 {
		t.Fatalf("one entry per file: %+v", rep.Unknown)
	}
}

// The glob is judged file by file, and the report aggregates the pairs.
func TestAGlobIsJudgedFileByFileAndTheReportAggregates(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"tokenfuse.ndjson":       envLine("tokenfuse", "a") + envLine("wardryx", "forged"),
		"wardryx.ndjson":         envLine("wardryx", "b"),
		"tokenfuse-cloud.ndjson": envLine("tokenfuse", "c") + envLine("wardryx", "forged2"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ids, _, rep, err := Load(filepath.Join(dir, "*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || rep.ForeignSource != 2 || len(rep.Foreign) != 2 {
		t.Fatalf("%d ids, ForeignSource = %d, %d pairs, want 3, 2, 2", len(ids), rep.ForeignSource, len(rep.Foreign))
	}
	if filepath.Base(rep.Foreign[0].File) != "tokenfuse-cloud.ndjson" || filepath.Base(rep.Foreign[1].File) != "tokenfuse.ndjson" {
		t.Fatalf("pairs must name their own files: %+v", rep.Foreign)
	}
}

// A producer minting a new claimed source per line cannot make the report the
// size of its log: the count stays whole, the named pairs stop at the bound.
func TestTheNamedPairsAreBoundedAndTheCountIsWhole(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxForeignPairs+30; i++ {
		b.WriteString(envLine(fmt.Sprintf("forged-%d", i), "a"))
	}
	p := writeStream(t, "tokenfuse.ndjson", b.String())
	_, _, rep, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ForeignSource != maxForeignPairs+30 {
		t.Fatalf("the count must be whole: %d", rep.ForeignSource)
	}
	if len(rep.Foreign) != maxForeignPairs {
		t.Fatalf("named pairs = %d, want the bound %d", len(rep.Foreign), maxForeignPairs)
	}
}

// Hostile bytes are malformed exactly as before and never reach the source
// check.
func TestHostileLinesStillCountAsMalformedNotForeign(t *testing.T) {
	p := writeStream(t, "tokenfuse.ndjson", "not json\n{\"source\":\"wardryx\"}\n\x00\x01\x02\n"+envLine("tokenfuse", "ok"))
	ids, _, rep, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || rep.Malformed != 3 || rep.ForeignSource != 0 {
		t.Fatalf("%d ids, Malformed = %d, ForeignSource = %d, want 1, 3, 0", len(ids), rep.Malformed, rep.ForeignSource)
	}
}

// Across a glob the named pairs stay bounded as they merge, and the count of
// refused events stays the whole sum.
func TestTheMergedReportBoundsTheNamedPairsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	for f := 0; f < 3; f++ {
		var b strings.Builder
		for i := 0; i < 30; i++ {
			b.WriteString(envLine(fmt.Sprintf("forged-%d-%d", f, i), "a"))
		}
		name := []string{"tokenfuse.ndjson", "tokenfuse-cloud.ndjson", "tokenfuse-mcp.ndjson"}[f]
		if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, rep, err := Load(filepath.Join(dir, "*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ForeignSource != 90 {
		t.Fatalf("the count must be the whole sum across files: %d", rep.ForeignSource)
	}
	if len(rep.Foreign) != maxForeignPairs {
		t.Fatalf("named pairs = %d after the merge, want the bound %d", len(rep.Foreign), maxForeignPairs)
	}

	// The same bound on undeclared streams: many files, one entry each.
	udir := t.TempDir()
	for i := 0; i < maxForeignPairs+5; i++ {
		name := fmt.Sprintf("plane%03d.ndjson", i)
		if err := os.WriteFile(filepath.Join(udir, name), []byte(envLine(fmt.Sprintf("plane%03d", i), "a")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, urep, err := Load(filepath.Join(udir, "*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if urep.UnknownStream != maxForeignPairs+5 || len(urep.Unknown) != maxForeignPairs {
		t.Fatalf("UnknownStream = %d, named = %d, want %d and %d", urep.UnknownStream, len(urep.Unknown), maxForeignPairs+5, maxForeignPairs)
	}
}
