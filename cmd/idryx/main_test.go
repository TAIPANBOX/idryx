package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/bom"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestMultiSourceStitchesAgentAndMCP is the regression test for the cross-layer
// gap: agent_shadow_tool can only fire when agents and mcp live in one graph.
// The CLI loads one source per file, so --load must stitch several sources
// together. This builds that combined graph and asserts the detector fires for
// the agent wired to a shadow MCP tool, and stays silent for clean agents.
func TestMultiSourceStitchesAgentAndMCP(t *testing.T) {
	loads := loadList{
		{Source: "agents", Path: "../../testdata/demo_agents.json"},
		{Source: "mcp", Path: "../../testdata/demo_mcp.json"},
	}
	g, err := buildGraph("", "", "", "", "", "", "", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	alerts := runDetectors(g)
	got := map[string]string{} // identity -> severity, for agent_shadow_tool only
	for _, a := range alerts {
		if a.Detector == "agent_shadow_tool" {
			got[a.IdentityID] = a.Severity.String()
		}
	}

	// ops-helper uses shell_exec (high-risk) from the rogue-shell shadow server.
	if sev, ok := got["agent:ops-helper"]; !ok {
		t.Error("expected agent:ops-helper to be flagged by agent_shadow_tool")
	} else if sev != "critical" {
		t.Errorf("agent:ops-helper severity = %q, want critical (high-risk tool)", sev)
	}

	// notetaker uses note_fetch from rogue-notes (not high-risk) -> high.
	if sev, ok := got["agent:notetaker"]; !ok {
		t.Error("expected agent:notetaker to be flagged by agent_shadow_tool")
	} else if sev != "high" {
		t.Errorf("agent:notetaker severity = %q, want high", sev)
	}

	// clean-bot only uses sanctioned github-mcp tools -> must not be flagged.
	if _, ok := got["agent:clean-bot"]; ok {
		t.Error("agent:clean-bot uses only sanctioned tools; must not be flagged")
	}
}

func TestLoadListSet(t *testing.T) {
	var l loadList
	if err := l.Set("agents:a.json"); err != nil {
		t.Fatal(err)
	}
	if err := l.Set("mcp:m.json"); err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[0].Source != "agents" || l[0].Path != "a.json" || l[1].Source != "mcp" {
		t.Errorf("unexpected loadList: %+v", l)
	}
	if err := l.Set("bogus"); err == nil {
		t.Error("expected error for missing colon")
	}
	if err := l.Set(":nopath"); err == nil {
		t.Error("expected error for empty source")
	}
}

func TestHeaderListSet(t *testing.T) {
	h := headerList{}
	if err := h.Set("Authorization: Bearer k"); err != nil {
		t.Fatal(err)
	}
	// A value with its own colons (a URL, a timestamp) must survive intact:
	// only the FIRST colon separates the name from the value.
	if err := h.Set("X-Origin: https://idryx.internal:8443/detect"); err != nil {
		t.Fatal(err)
	}
	if h["Authorization"] != "Bearer k" || h["X-Origin"] != "https://idryx.internal:8443/detect" {
		t.Errorf("unexpected headers: %+v", h)
	}
	// A malformed header is refused rather than dropped: silently sending an
	// unauthenticated request would look like a delivery failure at the far
	// end, which is the hardest kind of misconfiguration to find.
	for _, bad := range []string{"nocolon", ": novalue", "NoValue:", "  : "} {
		if err := h.Set(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

// TestRunDetectOTLPWiring is the CLI-level wiring check for the OTLP sink:
// IDRYX_OTLP_ENDPOINT unset must construct no sink and make no network call
// (zero behavior change for anyone not using it), and setting it must
// deliver the run's alerts to the configured collector.
func TestRunDetectOTLPWiring(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// --privileged bob/carol makes mfa_fatigue and new_device fire at high
	// severity or above on events.json, so the default --min-severity high
	// threshold delivers alerts without needing to lower it.
	args := []string{"-privileged", "bob@example.com,carol@example.com", "../../testdata/events.json"}

	captureStdout(t, func() {
		if err := runDetect(args); err != nil {
			t.Fatalf("runDetect: %v", err)
		}
	})
	if calls != 0 {
		t.Fatalf("IDRYX_OTLP_ENDPOINT unset: got %d OTLP call(s), want 0", calls)
	}

	t.Setenv("IDRYX_OTLP_ENDPOINT", srv.URL)
	captureStdout(t, func() {
		if err := runDetect(args); err != nil {
			t.Fatalf("runDetect: %v", err)
		}
	})
	if calls != 1 {
		t.Fatalf("IDRYX_OTLP_ENDPOINT set: got %d OTLP call(s), want 1", calls)
	}
}

// TestLoadTokenFuseStitchesIdentitiesAndEvents is the CLI-level wiring check
// for the tokenfuse connector (agent-passport SPEC §6.3): --load tokenfuse:path
// must populate the graph with both the agent/human identities and the
// behavioral events from the same NDJSON file, and the delegation chain
// carried in on_behalf_of must survive into the graph unchanged.
func TestLoadTokenFuseStitchesIdentitiesAndEvents(t *testing.T) {
	loads := loadList{
		{Source: "tokenfuse", Path: "../../testdata/tokenfuse.ndjson"},
	}
	g, err := buildGraph("", "", "", "", "", "", "", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	ids := g.Identities()
	if len(ids) != 4 {
		t.Fatalf("got %d identities, want 4 (2 agents seen directly + 1 sub-agent + 1 human)", len(ids))
	}

	var sub *model.Identity
	var totalEvents int
	for _, id := range ids {
		totalEvents += len(id.Events)
		if id.ID == "agent://acme-bank.example/support/sub-agent" {
			sub = id
		}
	}
	if totalEvents != 10 {
		t.Errorf("total events across the graph = %d, want 10", totalEvents)
	}
	if sub == nil {
		t.Fatal("expected agent://acme-bank.example/support/sub-agent in the graph")
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
}

// TestLoadAgentBusSourcesAttributeCorrectSource is the CLI-level wiring
// check for the three new agent-event-bus prefixes (agent-passport SPEC
// §6.3): --load wardryx:/mockryx:/verdryx:<path> must all reach ingestion
// through the same connector as --load tokenfuse:<path> (no "unknown
// source" error), and every identity/event they produce in the graph must
// be attributed to its own real source, never the literal "tokenfuse" the
// connector package happens to be named after.
func TestLoadAgentBusSourcesAttributeCorrectSource(t *testing.T) {
	tests := []struct {
		source string
		path   string
	}{
		{"wardryx", "../../internal/ingest/tokenfuse/testdata/wardryx/events.ndjson"},
		{"mockryx", "../../internal/ingest/tokenfuse/testdata/mockryx/events.ndjson"},
		{"verdryx", "../../internal/ingest/tokenfuse/testdata/verdryx/events.ndjson"},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			loads := loadList{{Source: tt.source, Path: tt.path}}
			g, err := buildGraph("", "", "", "", "", "", "", loads)
			if err != nil {
				t.Fatalf("buildGraph --load %s:%s: %v", tt.source, tt.path, err)
			}

			ids := g.Identities()
			if len(ids) == 0 {
				t.Fatal("expected at least one identity in the graph")
			}
			sawEvent := false
			for _, id := range ids {
				if id.Source != tt.source {
					t.Errorf("identity %s Source = %q, want %q", id.ID, id.Source, tt.source)
				}
				for _, e := range id.Events {
					sawEvent = true
					if e.Source != tt.source {
						t.Errorf("event %s/%s Source = %q, want %q", id.ID, e.Type, e.Source, tt.source)
					}
				}
			}
			if !sawEvent {
				t.Error("expected at least one event in the graph")
			}
		})
	}
}

// TestLoadWholeAgentEventBusStitchesAllProducers is the end-to-end proof
// that idryx can ingest the whole agent-event bus into one graph: TokenFuse,
// Wardryx, Mockryx and Verdryx all emit events for the same agent
// (agent://.../tier1-bot), and stitching all four --load sources together
// must merge them onto one identity node, each event keeping its own
// producer's Source rather than collapsing to "tokenfuse".
func TestLoadWholeAgentEventBusStitchesAllProducers(t *testing.T) {
	loads := loadList{
		{Source: "tokenfuse", Path: "../../internal/ingest/tokenfuse/testdata/events.ndjson"},
		{Source: "wardryx", Path: "../../internal/ingest/tokenfuse/testdata/wardryx/events.ndjson"},
		{Source: "mockryx", Path: "../../internal/ingest/tokenfuse/testdata/mockryx/events.ndjson"},
		{Source: "verdryx", Path: "../../internal/ingest/tokenfuse/testdata/verdryx/events.ndjson"},
	}
	g, err := buildGraph("", "", "", "", "", "", "", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	byID := map[string]*model.Identity{}
	var totalEvents int
	for _, id := range g.Identities() {
		byID[id.ID] = id
		totalEvents += len(id.Events)
	}
	if totalEvents != 17 { // 10 tokenfuse + 3 wardryx + 2 mockryx + 2 verdryx
		t.Errorf("total events across the graph = %d, want 17", totalEvents)
	}

	tier1 := byID["agent://acme-bank.example/support/tier1-bot"]
	if tier1 == nil {
		t.Fatal("expected tier1-bot in the graph")
	}
	gotSources := map[string]bool{}
	for _, e := range tier1.Events {
		gotSources[e.Source] = true
	}
	for _, want := range []string{"tokenfuse", "wardryx", "mockryx", "verdryx"} {
		if !gotSources[want] {
			t.Errorf("tier1-bot events missing a %s-sourced event; got sources %v", want, gotSources)
		}
	}

	// sub-agent only appears in the tokenfuse fixture: single-producer, so
	// its Identity.Source is unambiguous.
	sub := byID["agent://acme-bank.example/support/sub-agent"]
	if sub == nil {
		t.Fatal("expected sub-agent (tokenfuse-only) in the graph")
	}
	if sub.Source != "tokenfuse" {
		t.Errorf("sub-agent Source = %q, want tokenfuse", sub.Source)
	}
}

// TestBuildGraphLayersPassports is the CLI-level wiring check for
// --passports: it enriches an identity already produced by another source
// (here, an agent tokenfuse also observed) with static Passport metadata,
// and adds an identity that exists only as a Passport (no behavioral events
// at all) as its own agent identity.
func TestBuildGraphLayersPassports(t *testing.T) {
	loads := loadList{
		{Source: "tokenfuse", Path: "../../testdata/tokenfuse.ndjson"},
	}
	g, err := buildGraph("", "", "", "", "", "", "../../testdata/passports", loads)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}

	byID := map[string]*model.Identity{}
	for _, id := range g.Identities() {
		byID[id.ID] = id
	}

	tier1 := byID["agent://acme-bank.example/support/tier1-bot"]
	if tier1 == nil {
		t.Fatal("expected tier1-bot (from tokenfuse) in the graph")
	}
	if tier1.Attestation != "spiffe-svid" {
		t.Errorf("tier1-bot Attestation = %q, want spiffe-svid (from passport)", tier1.Attestation)
	}
	if tier1.Parent != "agent://acme-bank.example/support/orchestrator" {
		t.Errorf("tier1-bot Parent = %q, want agent://acme-bank.example/support/orchestrator", tier1.Parent)
	}
	if len(tier1.Events) == 0 {
		t.Error("tier1-bot should keep its tokenfuse events after passport enrichment merges in")
	}

	standalone := byID["agent://acme-bank.example/eng/standalone"]
	if standalone == nil {
		t.Fatal("expected standalone (passport-only) agent in the graph")
	}
	if standalone.Attestation != "none" {
		t.Errorf("standalone Attestation = %q, want none", standalone.Attestation)
	}
	if standalone.Type != model.IdentityAgent {
		t.Errorf("standalone Type = %q, want agent", standalone.Type)
	}
}

// TestBomBuildOverAgentsSource is the CLI-level wiring check for `idryx bom`:
// it must build its graph through the same buildGraph path detect uses, and
// bom.Build must see the resulting agent identities with their tools intact.
func TestBomBuildOverAgentsSource(t *testing.T) {
	g, err := buildGraph("agents", "", "../../testdata/demo_agents.json", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("buildGraph: %v", err)
	}
	b := bom.Build(g)
	if len(b.Agents) != 3 {
		t.Fatalf("got %d agents, want 3", len(b.Agents))
	}

	byID := map[string]bom.AgentBOM{}
	for _, a := range b.Agents {
		byID[a.ID] = a
	}
	helper, ok := byID["agent:ops-helper"]
	if !ok {
		t.Fatal("expected agent:ops-helper in the BOM")
	}
	if !helper.Privileged {
		t.Error("agent:ops-helper holds shell_exec (admin-equivalent); should be privileged")
	}
	foundAdminTool := false
	for _, tool := range helper.Tools {
		if tool.Name == "shell_exec" && tool.Admin {
			foundAdminTool = true
		}
	}
	if !foundAdminTool {
		t.Errorf("agent:ops-helper tools missing admin shell_exec: %+v", helper.Tools)
	}

	// demo_agents.json never sets attestation, so the BOM should faithfully
	// show that gap rather than inventing a value.
	for id, a := range byID {
		if a.Attestation != "" {
			t.Errorf("%s: Attestation = %q, want empty (demo_agents.json has no attestation field)", id, a.Attestation)
		}
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it, so the runBom smoke tests below can assert on
// its actual printed output instead of only its error return.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(data)
}

// TestRunBomJSONSmoke is the CLI-level smoke test for `idryx bom`: real flag
// parsing, the same buildGraph path detect uses, bom.Build, and JSON
// rendering, all wired together end to end and printing valid CycloneDX JSON.
func TestRunBomJSONSmoke(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runBom([]string{"-source", "agents", "../../testdata/demo_agents.json"}); err != nil {
			t.Fatalf("runBom: %v", err)
		}
	})

	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("runBom -format json did not print valid JSON: %v\n%s", err, out)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	comps, ok := doc["components"].([]any)
	if !ok || len(comps) != 3 {
		t.Errorf("components = %v, want 3 entries (ops-helper, notetaker, clean-bot)", doc["components"])
	}
}

// TestRunBomHumanSmoke exercises the -format human path end to end.
func TestRunBomHumanSmoke(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runBom([]string{"-source", "agents", "-format", "human", "../../testdata/demo_agents.json"}); err != nil {
			t.Fatalf("runBom: %v", err)
		}
	})
	if !strings.Contains(out, "idryx agent-bom: 3 agent(s)") {
		t.Errorf("human output missing summary line:\n%s", out)
	}
	if !strings.Contains(out, "agent:ops-helper") {
		t.Errorf("human output missing agent:ops-helper:\n%s", out)
	}
}

// TestRunBomUnknownFormat asserts an invalid -format is a hard error, the
// same contract runDetect gives its own -format flag.
func TestRunBomUnknownFormat(t *testing.T) {
	err := runBom([]string{"-source", "agents", "-format", "bogus", "../../testdata/demo_agents.json"})
	if err == nil {
		t.Fatal("expected an error for an unknown -format")
	}
}

// TestServeDefaultAddrIsLoopback is the regression test for `idryx serve`
// binding every interface by default. SECURITY.md documents /api/alerts,
// /api/identities and /api/remediations as having no authentication,
// authorization, CORS policy or rate limiting, on the assumption that the
// operator reaches the dashboard over a WireGuard/SSH tunnel -- a deliberate,
// documented constraint. Defaulting the *bind* to every interface made that
// constraint easy to violate by accident: a naive `idryx serve <log.json>`
// with no flags exposed the whole identity graph to the network. Kept
// simple and direct per instruction: this is a property of a constant, so it
// is asserted directly, with no listener or network call involved.
func TestServeDefaultAddrIsLoopback(t *testing.T) {
	host, _, err := net.SplitHostPort(defaultServeAddr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q): %v", defaultServeAddr, err)
	}
	if !isLoopbackHost(host) {
		t.Errorf("defaultServeAddr = %q: host %q is not loopback-only, so a bare "+
			"`idryx serve <log.json>` binds every interface on a dashboard "+
			"SECURITY.md documents as having no authentication", defaultServeAddr, host)
	}
}

// TestIsLoopbackHost pins the loopback classification isLoopbackHost makes,
// including the ":8080"-style empty host (net.SplitHostPort's shape for an
// address with no host part), which means "every interface" in net/http and
// must NOT be treated as loopback.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.5.5.5", true}, // the whole 127.0.0.0/8 block is loopback, not just .1
		{"localhost", true},
		{"LOCALHOST", true},
		{"::1", true},
		{"", false}, // ":8080" -> SplitHostPort gives an empty host -> all interfaces
		{"0.0.0.0", false},
		{"10.0.0.5", false},
		{"idryx.internal", false},
	}
	for _, c := range cases {
		if got := isLoopbackHost(c.host); got != c.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestWarnIfNonLoopback is the regression test for the loud-warning half of
// the fix (mirroring tokenfuse's TOKENFUSE_CLOUD_HOST precedent,
// crates/cloud/src/main.rs): an operator who deliberately widens -addr must
// still see, unmissably, that the dashboard SECURITY.md documents as
// unauthenticated is now reachable from the network. A loopback bind must
// print nothing.
func TestWarnIfNonLoopback(t *testing.T) {
	cases := []struct {
		addr     string
		wantWarn bool
	}{
		{"127.0.0.1:8080", false},
		{"localhost:8080", false},
		{"[::1]:8080", false},
		{":8080", true},
		{"0.0.0.0:8080", true},
		{"10.0.0.5:8080", true},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		warnIfNonLoopback(&buf, c.addr)
		got := buf.Len() > 0
		if got != c.wantWarn {
			t.Errorf("warnIfNonLoopback(%q): wrote output = %v, want %v (output: %q)", c.addr, got, c.wantWarn, buf.String())
		}
		if got && !strings.Contains(buf.String(), c.addr) {
			t.Errorf("warnIfNonLoopback(%q): warning does not name the address it warned about: %q", c.addr, buf.String())
		}
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it, mirroring captureStdout.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(data)
}

// TestReportIngestStderrSummary is the regression test for the stderr half
// of the malformed-record fix: reportIngest must print a summary naming the
// source, path and count when anything was dropped, and print nothing when
// nothing was, mirroring reportTokenFuse/reportPassports' existing contract.
func TestReportIngestStderrSummary(t *testing.T) {
	out := captureStderr(t, func() {
		reportIngest("okta", "events.json", ingest.Report{Records: 3, Malformed: 1})
	})
	if !strings.Contains(out, "okta") || !strings.Contains(out, "events.json") || !strings.Contains(out, "1 malformed") {
		t.Errorf("expected a summary naming the source, path and malformed count, got %q", out)
	}

	clean := captureStderr(t, func() {
		reportIngest("okta", "events.json", ingest.Report{Records: 3, Malformed: 0})
	})
	if clean != "" {
		t.Errorf("expected no output for a clean report, got %q", clean)
	}
}

// TestPopulateSurfacesMalformedRecordsOnStderr is the CLI-level wiring check
// for the malformed-record fix: a real --load okta:<path> batch with one
// unparseable timestamp must print reportIngest's summary on stderr, and a
// clean batch must print nothing. This exercises the real path (populate ->
// parseSource -> ingest.Okta -> reportIngest), not the helper in isolation,
// so a wiring mistake (e.g. the wrong spec.Path passed through) would still
// be caught even if reportIngest itself is correct.
func TestPopulateSurfacesMalformedRecordsOnStderr(t *testing.T) {
	dirty := filepath.Join(t.TempDir(), "okta.json")
	dirtyData := []byte(`[
		{"published":"2026-05-29T10:00:00Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"alice@example.com"}},
		{"published":"not-a-timestamp","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"mallory@example.com"}}
	]`)
	if err := os.WriteFile(dirty, dirtyData, 0o600); err != nil {
		t.Fatal(err)
	}

	loads := loadList{{Source: "okta", Path: dirty}}
	out := captureStderr(t, func() {
		if _, err := buildGraph("", "", "", "", "", "", "", loads); err != nil {
			t.Fatalf("buildGraph: %v", err)
		}
	})
	if !strings.Contains(out, "okta") || !strings.Contains(out, dirty) || !strings.Contains(out, "1 malformed") {
		t.Errorf("expected the malformed-record summary (source, path, count) on stderr, got %q", out)
	}

	clean := filepath.Join(t.TempDir(), "okta_clean.json")
	cleanData := []byte(`[
		{"published":"2026-05-29T10:00:00Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"alice@example.com"}}
	]`)
	if err := os.WriteFile(clean, cleanData, 0o600); err != nil {
		t.Fatal(err)
	}

	loads2 := loadList{{Source: "okta", Path: clean}}
	out2 := captureStderr(t, func() {
		if _, err := buildGraph("", "", "", "", "", "", "", loads2); err != nil {
			t.Fatalf("buildGraph: %v", err)
		}
	})
	if out2 != "" {
		t.Errorf("expected no stderr output for a clean batch, got %q", out2)
	}
}
