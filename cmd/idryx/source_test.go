package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse"
)

// These tests are the behaviour of invariant 17: an event is ingested into the
// identity graph as the source it claims only when the file it was read from
// may carry that source. They go through buildGraph and runDetect, the doors an
// operator uses, and read only the graph and stderr.

// busLine is one valid envelope claiming the given source, about one agent.
func busLine(source, agent string) string {
	return `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-10-04T10:00:00Z",` +
		`"source":"` + source + `","type":"spend_spike","severity":"high",` +
		`"agent_id":"agent://acme.example/` + agent + `","run_id":"run-1"}` + "\n"
}

// busDir writes name -> content into a fresh directory and returns it.
func busDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// loadBus ingests one --load spec and returns the graph and what was said.
func loadBus(t *testing.T, source, path string) (graph.Reader, string) {
	t.Helper()
	var g graph.Reader
	out := captureStderr(t, func() {
		var err error
		g, err = buildGraph("", "", "", "", "", "", "", loadList{{Source: source, Path: path}})
		if err != nil {
			t.Fatalf("buildGraph --load %s:%s: %v", source, path, err)
		}
	})
	return g, out
}

func hasAgent(g graph.Reader, agent string) bool {
	for _, id := range g.Identities() {
		if id.ID == "agent://acme.example/"+agent {
			return true
		}
	}
	return false
}

func eventsBySource(g graph.Reader) map[string]int {
	out := map[string]int{}
	for _, id := range g.Identities() {
		for _, e := range id.Events {
			out[e.Source]++
		}
	}
	return out
}

// The defect: a line claiming `source: wardryx` inside tokenfuse.ndjson was
// ingested as a wardryx event about an agent nobody established, and the
// identity graph grew a node for it.
func TestALineClaimingAnotherSourceIsNotIngestedAsThatSource(t *testing.T) {
	dir := busDir(t, map[string]string{
		"tokenfuse.ndjson": busLine("tokenfuse", "legit") + busLine("wardryx", "forged"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "tokenfuse.ndjson"))

	if hasAgent(g, "forged") {
		t.Fatalf("an agent that only a line claiming wardryx inside tokenfuse.ndjson named is in the graph")
	}
	if !hasAgent(g, "legit") {
		t.Fatalf("the legitimate line's agent was lost")
	}
	if got := eventsBySource(g); got["wardryx"] != 0 || got["tokenfuse"] != 1 {
		t.Fatalf("events by source = %v, want one tokenfuse and no wardryx", got)
	}
	for _, want := range []string{"tokenfuse.ndjson", "wardryx", "not ingested"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr does not say %q:\n%s", want, out)
		}
	}
}

// The refusal is reported, never fatal: the same posture as a broken chain.
// An identity tool that stops reading because a file holds a foreign line
// has been talked out of the rest of that file by whoever wrote the line.
func TestARefusalIsReportedAndNeverFatal(t *testing.T) {
	dir := busDir(t, map[string]string{
		"tokenfuse.ndjson": busLine("wardryx", "forged") + busLine("tokenfuse", "legit"),
	})
	path := filepath.Join(dir, "tokenfuse.ndjson")
	var runErr error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			runErr = runDetect([]string{"--load", "tokenfuse:" + path})
		})
	})
	if runErr != nil {
		t.Fatalf("detect over a file with a refused line failed: %v", runErr)
	}
	if !strings.Contains(stderr, "not ingested") {
		t.Fatalf("the refusal was not reported on stderr:\n%s", stderr)
	}
}

// A glob applies the rule to each file by its own name: a line claiming
// wardryx is refused in tokenfuse.ndjson and kept in wardryx.ndjson.
func TestAGlobAppliesTheRuleFileByFile(t *testing.T) {
	dir := busDir(t, map[string]string{
		"tokenfuse.ndjson": busLine("tokenfuse", "legit") + busLine("wardryx", "forged"),
		"wardryx.ndjson":   busLine("wardryx", "policy"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "*.ndjson"))

	if hasAgent(g, "forged") {
		t.Fatalf("the forged line was ingested through a glob")
	}
	if !hasAgent(g, "legit") || !hasAgent(g, "policy") {
		t.Fatalf("a legitimate line was lost through a glob; agents: %v", g.Identities())
	}
	if !strings.Contains(out, "tokenfuse.ndjson") {
		t.Errorf("the refusal must name the file it happened in:\n%s", out)
	}
}

// The measured multi-source file: `taipan demo` writes events attributed to six
// planes into demo.ndjson, and the exception table declares it.
func TestADeclaredMultiSourceFileIsIngestedWhole(t *testing.T) {
	dir := busDir(t, map[string]string{
		"demo.ndjson": busLine("tokenfuse", "a") + busLine("wardryx", "b") + busLine("mockryx", "c"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "demo.ndjson"))

	for _, agent := range []string{"a", "b", "c"} {
		if !hasAgent(g, agent) {
			t.Errorf("agent %s in the declared multi-source file was refused", agent)
		}
	}
	if strings.Contains(out, "not ingested") {
		t.Errorf("a declared file raised a refusal:\n%s", out)
	}
}

// The renamed files the money plane writes, each stamping `tokenfuse`.
func TestRenamedFilesOfTheSameProducerAreIngested(t *testing.T) {
	dir := busDir(t, map[string]string{
		"tokenfuse-cloud.ndjson": busLine("tokenfuse", "cloud"),
		"tokenfuse-mcp.ndjson":   busLine("tokenfuse", "mcp"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "*.ndjson"))
	if !hasAgent(g, "cloud") || !hasAgent(g, "mcp") {
		t.Fatalf("a renamed tokenfuse file was refused; stderr:\n%s", out)
	}
	if strings.Contains(out, "not ingested") {
		t.Errorf("a renamed tokenfuse file raised a refusal:\n%s", out)
	}
}

// A stream nothing declares is not trusted in silence and not dropped: a line
// claiming the stream's own name is ingested and the stream is named on stderr,
// a line claiming anything else is refused.
func TestAnUnknownStreamIsIngestedAndNamedNotTrustedInSilence(t *testing.T) {
	dir := busDir(t, map[string]string{
		"newplane.ndjson": busLine("newplane", "np") + busLine("tokenfuse", "forged"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "newplane.ndjson"))

	if !hasAgent(g, "np") {
		t.Fatalf("a line from a stream this build has not heard of was dropped")
	}
	if hasAgent(g, "forged") {
		t.Fatalf("a line claiming tokenfuse inside newplane.ndjson was ingested as tokenfuse")
	}
	if !strings.Contains(out, "newplane.ndjson") || !strings.Contains(out, "not a stream this build knows") {
		t.Errorf("an unknown stream must be named on stderr:\n%s", out)
	}
}

// The operator declares what a file of their own may carry; undeclared, an
// events.ndjson holding several planes' lines is refused.
func TestAFileNamedEventsIsRefusedUntilItsSourcesAreDeclared(t *testing.T) {
	for _, tc := range []struct {
		name, streams string
		wantIngested  bool
	}{
		{"undeclared", "", false},
		{"declared", "events=tokenfuse|wardryx", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IDRYX_STREAMS", tc.streams)
			dir := busDir(t, map[string]string{
				"events.ndjson": busLine("tokenfuse", "t") + busLine("wardryx", "w"),
			})
			g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "events.ndjson"))
			got := hasAgent(g, "t") && hasAgent(g, "w")
			if got != tc.wantIngested {
				t.Fatalf("streams=%q: ingested = %v, want %v; stderr:\n%s", tc.streams, got, tc.wantIngested, out)
			}
			if tc.wantIngested && strings.Contains(out, "not ingested") {
				t.Errorf("a declared file raised a refusal:\n%s", out)
			}
		})
	}
}

// Hostile lines are unchanged by the rule: garbage and truncated envelopes stay
// malformed, and a claimed source that tries to break the report stays on one
// line of stderr.
func TestHostileLinesAreUnchangedAndAHostileClaimStaysOnOneLine(t *testing.T) {
	hostile := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-10-04T10:00:00Z",` +
		`"source":"wardryx\r\nBcc: attacker@example.com","type":"spend_spike","severity":"high",` +
		`"agent_id":"agent://acme.example/hostile","run_id":"run-h"}` + "\n"
	dir := busDir(t, map[string]string{
		"tokenfuse.ndjson": "not json at all\n" + `{"source":"tokenfuse"}` + "\n" + hostile + busLine("tokenfuse", "legit"),
	})
	g, out := loadBus(t, "tokenfuse", filepath.Join(dir, "tokenfuse.ndjson"))

	if !hasAgent(g, "legit") {
		t.Fatalf("the legitimate line was lost among hostile ones")
	}
	if hasAgent(g, "hostile") {
		t.Fatalf("the hostile line was ingested as the source it claimed")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Fatalf("a claimed source forged a line of its own on stderr: %q", line)
		}
	}
	if !strings.Contains(out, "2 malformed") {
		t.Errorf("the two broken lines must still count as malformed, as before:\n%s", out)
	}
}

// A refused line still belongs to the file as written, so the prev_hash chain
// is verified over all of it: editing a line's source breaks the chain at the
// next line AND gets the line refused, and both are said.
func TestARefusedLineStillTakesPartInTheChainVerdict(t *testing.T) {
	_, lines := chainedFixture(t, 4)
	lines[1] = strings.Replace(lines[1], `"source":"tokenfuse"`, `"source":"wardryx"`, 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "tokenfuse.ndjson")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, out := loadBus(t, "tokenfuse", path)

	if !strings.Contains(out, "BROKEN") || !strings.Contains(out, "line 3") {
		t.Errorf("the edited line must break the chain at the next one, and say so:\n%s", out)
	}
	if got := eventsBySource(g); got["wardryx"] != 0 || got["tokenfuse"] != 3 {
		t.Errorf("events by source = %v, want three tokenfuse and the edited line refused", got)
	}
}

// A malformed declaration refuses the load and names the variable: the rule
// fails closed, and a declaration silently ignored would read as a producer
// that stopped being heard.
func TestAMalformedStreamDeclarationRefusesTheLoadNamingTheVariable(t *testing.T) {
	t.Setenv("IDRYX_STREAMS", "events")
	dir := busDir(t, map[string]string{"tokenfuse.ndjson": busLine("tokenfuse", "a")})
	_, err := buildGraph("", "", "", "", "", "", "", loadList{{Source: "tokenfuse", Path: filepath.Join(dir, "tokenfuse.ndjson")}})
	if err == nil {
		t.Fatal("a declaration with no sources was accepted")
	}
	if !strings.Contains(err.Error(), "IDRYX_STREAMS") {
		t.Fatalf("the error must name the variable: %v", err)
	}
}

// The report is one line per pair, bounded, and the claimed source is printed
// escaped: it is written by whoever the operator is trying to tell apart from a
// legitimate producer.
func TestTheStreamReportIsOneEscapedLinePerPair(t *testing.T) {
	rep := tokenfuse.Report{
		ForeignSource: 7,
		Foreign: []tokenfuse.Foreign{
			{File: "/x/tokenfuse.ndjson", Stem: "tokenfuse", Claimed: "wardryx", Count: 5, Allowed: []string{"tokenfuse"}},
			{File: "/x/tokenfuse.ndjson", Stem: "tokenfuse", Claimed: "wardryx\r\nBcc: attacker@example.com", Count: 2, Allowed: []string{"tokenfuse"}},
		},
		UnknownStream: 3,
		Unknown:       []tokenfuse.UnknownFile{{File: "/x/newplane.ndjson", Stem: "newplane", Count: 3}},
	}
	out := captureStderr(t, func() { reportStreams("tokenfuse", "/x/*.ndjson", rep) })

	for _, want := range []string{
		"7 event(s) not ingested",
		`tokenfuse.ndjson" claims "wardryx" 5 time(s); it may carry "tokenfuse".`,
		"IDRYX_STREAMS=tokenfuse=wardryx",
		"newplane.ndjson",
		"not a stream this build knows",
		"IDRYX_STREAMS=newplane=newplane",
		"The names are not plain names, so there is nothing to declare.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr does not say %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "idryx:") {
			t.Fatalf("a claimed source broke out of its line: %q", line)
		}
	}
}

// Past the bound the report says how many more it did not name, like a chain
// break list does.
func TestTheStreamReportStopsNamingPairsPastTheBound(t *testing.T) {
	var pairs []tokenfuse.Foreign
	for i := 0; i < maxReportedBreaks+3; i++ {
		pairs = append(pairs, tokenfuse.Foreign{File: "/x/tokenfuse.ndjson", Stem: "tokenfuse", Claimed: fmt.Sprintf("f%d", i), Count: 1, Allowed: []string{"tokenfuse"}})
	}
	out := captureStderr(t, func() {
		reportStreams("tokenfuse", "/x/tokenfuse.ndjson", tokenfuse.Report{ForeignSource: len(pairs), Foreign: pairs})
	})
	if !strings.Contains(out, "and 3 more pair(s)") {
		t.Errorf("the overflow must be counted:\n%s", out)
	}
	if n := strings.Count(out, "claims"); n != maxReportedBreaks {
		t.Errorf("named %d pairs, want %d:\n%s", n, maxReportedBreaks, out)
	}
}

// Nothing refused and nothing unknown prints nothing, like the malformed count.
func TestACleanIngestSaysNothingAboutStreams(t *testing.T) {
	out := captureStderr(t, func() { reportStreams("tokenfuse", "x", tokenfuse.Report{Lines: 5}) })
	if out != "" {
		t.Errorf("a clean ingest printed %q", out)
	}
}
