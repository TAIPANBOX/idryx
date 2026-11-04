package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/idryx/internal/aiusage"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func usageSubject(t *testing.T, r aiusage.Report, subject, provider string) aiusage.SubjectRow {
	t.Helper()
	for _, row := range r.Subjects {
		if row.Subject == subject && row.Provider == provider {
			return row
		}
	}
	t.Fatalf("no subject row for %q / %q; rows: %+v", subject, provider, r.Subjects)
	return aiusage.SubjectRow{}
}

func usageSource(t *testing.T, r aiusage.Report, source string) aiusage.SourceRow {
	t.Helper()
	for _, row := range r.Sources {
		if row.Source == source {
			return row
		}
	}
	t.Fatalf("no source row for %q; rows: %+v", source, r.Sources)
	return aiusage.SourceRow{}
}

// TestTheReportAgreesWithUndeclaredLLMAndUnmanagedEgress holds the report to
// the detectors on the cases both of them judge. The report is a second
// implementation of "declared against seen", kept apart from the detectors on
// purpose (invariant 10), and two implementations of one comparison drift
// unless something holds them equal. This is that something: the agents the
// report names seen-but-not-declared are exactly the agents undeclared_llm
// fires for, and the processes it names seen-with-no-declaration are exactly
// the ones unmanaged_egress grades as having reached a model API.
func TestTheReportAgreesWithUndeclaredLLMAndUnmanagedEgress(t *testing.T) {
	g := graph.New(nil)
	agent := func(id string, declared ...model.DeclaredModel) {
		g.AddIdentity(model.Identity{ID: id, Type: model.IdentityAgent, Source: "passport", DeclaredModels: declared})
	}
	reach := func(id string, hosts ...string) {
		for _, h := range hosts {
			g.AddEvent(model.Event{IdentityID: id, Type: model.EventEgress, Resource: h})
		}
	}
	// Declares one provider, reaches another: drift.
	agent("agent://acme.example/drifter", model.DeclaredModel{Provider: "anthropic"})
	reach("agent://acme.example/drifter", "api.openai.com:443")
	// Declares what it reaches: no drift.
	agent("agent://acme.example/honest", model.DeclaredModel{Provider: "openai"})
	reach("agent://acme.example/honest", "api.openai.com:443")
	// Declares nothing: undeclared_llm leaves it to shadow_ai, and the report
	// names it as having nothing to compare with.
	agent("agent://acme.example/mute")
	reach("agent://acme.example/mute", "api.openai.com:443")
	// Names a host in its declaration: the detector exempts it, and so must the report.
	agent("agent://acme.example/pinned", model.DeclaredModel{Provider: "anthropic", Endpoint: "api.openai.com"})
	reach("agent://acme.example/pinned", "api.openai.com:443")
	// Reaches an undeclared provider on one host and a declared one on another.
	agent("agent://acme.example/both", model.DeclaredModel{Provider: "anthropic"})
	reach("agent://acme.example/both", "api.anthropic.com:443", "api.openai.com:443")
	// An unattributed process reaching a model API, and one reaching nothing of the kind.
	reach("proc:curl@cg7", "api.openai.com:443")
	reach("proc:ls", "example.com:443")

	report := aiInventoryReport(g, nil)

	fired := map[string]bool{}
	for _, a := range detectors.NewUndeclaredLLM().Detect(g) {
		fired[a.IdentityID] = true
	}
	named := map[string]bool{}
	for _, row := range report.Subjects {
		if row.Gap == aiusage.GapSeenNotDeclared {
			named[row.Subject] = true
		}
	}
	if !reflect.DeepEqual(fired, named) {
		t.Errorf("undeclared_llm fires for %v and the report names %v seen-but-not-declared", sortedSet(fired), sortedSet(named))
	}
	if len(fired) != 2 {
		t.Errorf("the case set is wrong: undeclared_llm fired for %v, want drifter and both", sortedSet(fired))
	}

	graded := map[string]bool{}
	for _, a := range detectors.NewUnmanagedEgress().Detect(g) {
		if a.Severity == model.SeverityHigh {
			graded[a.IdentityID] = true
		}
	}
	processes := map[string]bool{}
	for _, row := range report.Subjects {
		if row.Kind == "process" && row.Gap == aiusage.GapSeenNoDeclaration {
			processes[row.Subject] = true
		}
	}
	if !reflect.DeepEqual(graded, processes) {
		t.Errorf("unmanaged_egress grades %v as reaching a model API and the report names %v", sortedSet(graded), sortedSet(processes))
	}
	for _, row := range report.Subjects {
		if row.Subject == "proc:ls" {
			t.Errorf("a process that reached no model provider is a subject row: %+v", row)
		}
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestAIInventoryPerSubjectRowsAreWiredToTheRealVocabularyAndTheBus is the seam
// test for the per-subject rows, for the reason invariant 11 gives for the
// provider rows: every test inside internal/aiusage supplies its own host
// matcher and builds its own graph, so none of them can tell whether the real
// vocabulary, a real bus file and a real Passport reach the new rows. Here all
// three come through the doors the command uses.
func TestAIInventoryPerSubjectRowsAreWiredToTheRealVocabularyAndTheBus(t *testing.T) {
	dir := t.TempDir()
	bus := filepath.Join(dir, "tokenfuse.ndjson")
	var lines string
	for i, typ := range []string{"spend_spike", "sustained_loop"} {
		lines += fmt.Sprintf(`{"schema":%q,"ts":"2026-11-04T10:0%d:00Z","source":"tokenfuse","type":%q,"agent_id":"agent://acme.example/bot"}`+"\n",
			event.SchemaV02, i, typ)
	}
	if err := os.WriteFile(bus, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(dir, "egress.json")
	if err := os.WriteFile(captured, []byte(`{"flows":[{"time":"2026-11-04T10:00:00Z","identity":"proc:python3@cg9","destination":"api.anthropic.com:443","bytes":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	passports := filepath.Join(dir, "passports")
	if err := os.Mkdir(passports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(passports, "bot.json"), []byte(`{
	  "schema": "taipanbox.dev/agent-passport/v0.1",
	  "id": "agent://acme.example/bot",
	  "owner": "team@acme.example",
	  "attestation": { "method": "none" },
	  "models": [ { "provider": "Anthropic", "model": "claude-sonnet-5-5" } ]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var g graph.Reader
	captureStderr(t, func() {
		var err error
		g, err = buildGraph("", "", "", "", "", "", passports, loadList{{Source: "tokenfuse", Path: bus}, {Source: "egress", Path: captured}})
		if err != nil {
			t.Fatalf("buildGraph: %v", err)
		}
	})
	r := aiInventoryReport(g, nil)

	proc := usageSubject(t, r, "proc:python3@cg9", "anthropic")
	if proc.Gap != aiusage.GapSeenNoDeclaration || proc.Seen != aiusage.SeenEgress || proc.Kind != "process" {
		t.Errorf("the captured process = %+v, want a seen row with no declaration: the real vocabulary did not reach the per-subject rows", proc)
	}
	bot := usageSubject(t, r, "agent://acme.example/bot", "anthropic")
	if bot.Gap != aiusage.GapDeclaredBusOnly || !reflect.DeepEqual(bot.Models, []string{"claude-sonnet-5-5"}) {
		t.Errorf("the governed agent = %+v, want declared, active on the bus only, with its declared model", bot)
	}
	if !reflect.DeepEqual(bot.Bus, []aiusage.BusCount{{Source: "tokenfuse", Events: 2}}) {
		t.Errorf("bus = %+v, want the two tokenfuse events the file held", bot.Bus)
	}
	for source, want := range map[string]string{
		aiusage.SourceDeclared: "present", aiusage.SourceBus: "present", aiusage.SourceEgress: "present",
		aiusage.SourceEBPF: "present", aiusage.SourceCode: "absent",
	} {
		if got := usageSource(t, r, source).State; got != want {
			t.Errorf("source %s is %s, want %s", source, got, want)
		}
	}
}
