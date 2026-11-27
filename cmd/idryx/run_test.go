package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/ingest/passport"
	"github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// This file drives the CLI through run(), the function main() hands os.Args
// to, so each test exercises flag parsing, the input rule, the graph build and
// the rendering exactly as an operator's invocation would.

// unreachableDSN names a Postgres that cannot answer: port 1 on loopback
// refuses at once, so every --db path reaches its error without a database
// and without waiting on a timeout.
const unreachableDSN = "postgres://idryx@127.0.0.1:1/idryx?sslmode=disable&connect_timeout=2"

// runCLI runs the CLI with args and returns what it wrote to stdout and
// stderr and the error run() returned. Both streams are drained while the
// command runs, so a command that writes more than a pipe buffer cannot
// block on its own output.
func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr

	var stdout, stderr strings.Builder
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&stdout, rOut) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&stderr, rErr) }()

	runErr := run(args)

	_ = wOut.Close()
	_ = wErr.Close()
	wg.Wait()
	os.Stdout, os.Stderr = oldOut, oldErr
	return stdout.String(), stderr.String(), runErr
}

func wantErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

func TestRunWithNoCommandPrintsUsageAndFails(t *testing.T) {
	_, stderr, err := runCLI(t)
	wantErrContains(t, err, "no command given")
	if !strings.Contains(stderr, "usage: idryx <command>") {
		t.Errorf("no usage on stderr:\n%s", stderr)
	}
}

func TestRunUnknownCommandPrintsUsageAndNamesIt(t *testing.T) {
	_, stderr, err := runCLI(t, "dettect")
	wantErrContains(t, err, `unknown command "dettect"`)
	if !strings.Contains(stderr, "commands:") {
		t.Errorf("no command list on stderr:\n%s", stderr)
	}
}

func TestRunVersionPrintsTheBuildVersion(t *testing.T) {
	stdout, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if strings.TrimSpace(stdout) != "idryx "+version {
		t.Errorf("version printed %q, want %q", stdout, "idryx "+version)
	}
}

// TestRunDispatchesEverySubcommand proves each command name reaches its own
// handler: every case below fails with a message only that handler writes.
func TestRunDispatchesEverySubcommand(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"detect", "-format", "yaml", "../../testdata/events.json"}, `unknown format "yaml"`},
		{[]string{"bom", "-format", "yaml", "../../testdata/demo_agents.json"}, `unknown format "yaml"`},
		{[]string{"ai-inventory", "-format", "yaml", "../../testdata/demo_agents.json"}, `unknown format "yaml"`},
		{[]string{"serve", "-db", unreachableDSN}, "ping postgres"},
		{[]string{"load", "../../testdata/events.json"}, "load requires --db"},
		{[]string{"remediate", "-open-pr", "../../testdata/agents.json"}, "--open-pr requires --repo"},
		{[]string{"ebpf-capture", "-duration", "nonsense"}, "invalid value"},
	}
	for _, c := range cases {
		t.Run(c.args[0], func(t *testing.T) {
			_, _, err := runCLI(t, c.args...)
			wantErrContains(t, err, c.want)
		})
	}
}

// TestInputRuleRefusesAmbiguousInput covers the one rule every graph-reading
// command shares: exactly one of --db, --load, or a single file.
func TestInputRuleRefusesAmbiguousInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"load with db", []string{"detect", "-load", "agents:x.json", "-db", unreachableDSN}, "use --load on its own"},
		{"load with file", []string{"detect", "-load", "agents:x.json", "y.json"}, "use --load on its own"},
		{"db with file", []string{"detect", "-db", unreachableDSN, "y.json"}, "either --db or a file, not both"},
		{"nothing", []string{"detect"}, "provide exactly one input file"},
		{"two files", []string{"bom", "a.json", "b.json"}, "provide exactly one input file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := runCLI(t, c.args...)
			wantErrContains(t, err, c.want)
		})
	}
}

func TestDetectJSONPrintsTheAlertsAsAJSONArray(t *testing.T) {
	stdout, _, err := runCLI(t, "detect", "-format", "json", "-source", "agents", "../../testdata/agents.json")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	var alerts []map[string]any
	if err := json.Unmarshal([]byte(stdout), &alerts); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, stdout)
	}
	found := false
	for _, a := range alerts {
		if a["detector"] == "stale_nhi" && a["identity"] == "agent:deploy-bot" {
			found = true
		}
	}
	if !found {
		t.Errorf("stale_nhi for agent:deploy-bot missing from %d alert(s)", len(alerts))
	}
}

func TestDetectRefusesAnUnknownMinSeverity(t *testing.T) {
	_, _, err := runCLI(t, "detect", "-min-severity", "urgent", "../../testdata/events.json")
	wantErrContains(t, err, `invalid --min-severity "urgent"`)
}

func TestDetectRefusesAnUnknownSource(t *testing.T) {
	_, _, err := runCLI(t, "detect", "-source", "ldap", "../../testdata/events.json")
	wantErrContains(t, err, `unknown source "ldap"`)
}

func TestDetectReportsAnUnreadableInput(t *testing.T) {
	_, _, err := runCLI(t, "detect", filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestDetectWithDBThatCannotBeReachedFails(t *testing.T) {
	_, _, err := runCLI(t, "detect", "-db", unreachableDSN)
	wantErrContains(t, err, "ping postgres")
}

// TestDetectEventsJournalNeedsATrustDomain: a journal path with no domain
// would be created and stay empty forever, which reads as "no findings".
func TestDetectEventsJournalNeedsATrustDomain(t *testing.T) {
	t.Setenv("IDRYX_EVENTS", filepath.Join(t.TempDir(), "journal.ndjson"))
	t.Setenv("IDRYX_TRUST_DOMAIN", "")
	_, _, err := runCLI(t, "detect", "-source", "agents", "../../testdata/agents.json")
	wantErrContains(t, err, "IDRYX_TRUST_DOMAIN is not")
}

func TestDetectEventsJournalRefusesAnInvalidTrustDomain(t *testing.T) {
	t.Setenv("IDRYX_EVENTS", filepath.Join(t.TempDir(), "journal.ndjson"))
	t.Setenv("IDRYX_TRUST_DOMAIN", "Acme Example")
	_, _, err := runCLI(t, "detect", "-source", "agents", "../../testdata/agents.json")
	wantErrContains(t, err, "cannot form a subject")
}

// TestDetectWritesFindingsToTheEventsJournal checks the journal gets one
// envelope per agent finding, under the operator's domain, and that findings
// with no agent subject are counted out loud rather than dropped in silence.
func TestDetectWritesFindingsToTheEventsJournal(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "journal.ndjson")
	t.Setenv("IDRYX_EVENTS", journal)
	t.Setenv("IDRYX_TRUST_DOMAIN", "acme.example")

	if _, _, err := runCLI(t, "detect", "-source", "agents", "../../testdata/agents.json"); err != nil {
		t.Fatalf("detect: %v", err)
	}
	f, err := os.Open(journal)
	if err != nil {
		t.Fatalf("journal not written: %v", err)
	}
	defer f.Close()
	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("journal line is not JSON: %v\n%s", err, sc.Text())
		}
		if id, _ := ev["agent_id"].(string); !strings.HasPrefix(id, "agent://acme.example/") {
			t.Errorf("agent_id = %q, want it under agent://acme.example/", id)
		}
		if ev["source"] != "idryx" || ev["type"] != "identity_finding" {
			t.Errorf("envelope source/type = %v/%v, want idryx/identity_finding", ev["source"], ev["type"])
		}
		lines++
	}
	if lines == 0 {
		t.Fatal("journal is empty after a run that raised agent findings")
	}

	// Okta users are not agents: their findings are skipped and counted.
	t.Setenv("IDRYX_EVENTS", filepath.Join(t.TempDir(), "users.ndjson"))
	_, stderr, err := runCLI(t, append([]string{"detect"}, detectArgsFor()...)...)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if !strings.Contains(stderr, "had no agent subject and were not written") {
		t.Errorf("skipped findings not reported on stderr:\n%s", stderr)
	}
}

// TestDetectHeaderFileFromEnvironmentIsReadOnlyForAWebhook: the environment
// names the header file only when the flag does not, and only a webhook
// reads it, so a broken path fails a webhook run before any input is read
// and does nothing to a run that sends nothing.
func TestDetectHeaderFileFromEnvironmentIsReadOnlyForAWebhook(t *testing.T) {
	t.Setenv("IDRYX_WEBHOOK_HEADER_FILE", filepath.Join(t.TempDir(), "absent-headers"))

	_, _, err := runCLI(t, "detect", "-webhook", "http://127.0.0.1:1/hook", "-source", "agents", "../../testdata/agents.json")
	wantErrContains(t, err, "--webhook-header-file")

	if _, _, err := runCLI(t, "detect", "-source", "agents", "../../testdata/agents.json"); err != nil {
		t.Fatalf("a run with no webhook must not read the header file: %v", err)
	}
}

func TestDetectPassesCredentialWarningButNeverTheValue(t *testing.T) {
	_, stderr, _ := runCLI(t, "detect", "-webhook-header", "Authorization: Bearer test-not-a-secret", "-source", "agents", "../../testdata/agents.json")
	if !strings.Contains(stderr, "--webhook-header Authorization carries a credential") {
		t.Errorf("no credential warning:\n%s", stderr)
	}
	if strings.Contains(stderr, "test-not-a-secret") {
		t.Errorf("the header value was echoed to stderr:\n%s", stderr)
	}
}

func TestBomReportsAMissingPassportDirectory(t *testing.T) {
	_, _, err := runCLI(t, "bom", "-passports", filepath.Join(t.TempDir(), "none", "*.json"), "../../testdata/demo_agents.json")
	if err == nil {
		// An empty glob is not an error for the passport loader; a bad pattern is.
		_, _, err = runCLI(t, "bom", "-passports", "[", "../../testdata/demo_agents.json")
	}
	wantErrContains(t, err, "load passports")
}

func TestAIInventoryHumanStatesWhatWasNotMeasured(t *testing.T) {
	stdout, _, err := runCLI(t, "ai-inventory", "../../testdata/demo_agents.json")
	if err != nil {
		t.Fatalf("ai-inventory: %v", err)
	}
	if !strings.Contains(stdout, "code scan: none supplied, so the CODE column is not a measurement") {
		t.Errorf("an absent code scan must be stated, not shown as zeros:\n%s", stdout)
	}
	if !strings.Contains(stdout, "agent:ops-helper") {
		t.Errorf("agent:ops-helper missing from the per-subject table:\n%s", stdout)
	}
}

func TestAIInventoryJSONCarriesTheVersion(t *testing.T) {
	stdout, _, err := runCLI(t, "ai-inventory", "-format", "json", "../../testdata/demo_agents.json")
	if err != nil {
		t.Fatalf("ai-inventory: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if doc["tool"] != "idryx "+version {
		t.Errorf("tool = %v, want %q", doc["tool"], "idryx "+version)
	}
	if doc["schema"] != "idryx.ai-inventory/v1" {
		t.Errorf("schema = %v, want idryx.ai-inventory/v1", doc["schema"])
	}
}

func TestAIInventoryRefusesAnUnreadableCodeScan(t *testing.T) {
	_, _, err := runCLI(t, "ai-inventory", "-code-scan", filepath.Join(t.TempDir(), "absent.json"), "../../testdata/demo_agents.json")
	wantErrContains(t, err, "read --code-scan")
}

func TestAIInventoryRefusesAmbiguousInput(t *testing.T) {
	_, _, err := runCLI(t, "ai-inventory")
	wantErrContains(t, err, "provide exactly one input file")
}

func TestAIInventoryReportsAGraphThatFailsToBuild(t *testing.T) {
	_, _, err := runCLI(t, "ai-inventory", "-source", "ldap", "../../testdata/events.json")
	wantErrContains(t, err, `unknown source "ldap"`)
}

// TestServeAnnouncesTheDashboardThenReportsAFailedListen runs serve all the
// way to the listener. An invalid port makes ListenAndServe return at once,
// so the banner, the warning and the error are all observable without
// leaving a server running.
func TestServeAnnouncesTheDashboardThenReportsAFailedListen(t *testing.T) {
	_, stderr, err := runCLI(t, "serve", "-refresh", "0", "-addr", "127.0.0.1:-1", "../../testdata/events.json")
	if err == nil {
		t.Fatal("expected the listener to fail on an invalid port")
	}
	if !strings.Contains(stderr, "serving dashboard on http://127.0.0.1:-1 (") {
		t.Errorf("banner missing:\n%s", stderr)
	}
	if !strings.Contains(stderr, "static (refresh off)") {
		t.Errorf("refresh 0 must be stated as static:\n%s", stderr)
	}
	if strings.Contains(stderr, "not loopback-only") {
		t.Errorf("a loopback bind must not warn:\n%s", stderr)
	}
}

func TestServeOnABarePortShowsLocalhostAndWarns(t *testing.T) {
	_, stderr, err := runCLI(t, "serve", "-refresh", "1h", "-addr", ":-1", "../../testdata/events.json")
	if err == nil {
		t.Fatal("expected the listener to fail on an invalid port")
	}
	if !strings.Contains(stderr, "http://localhost:-1") {
		t.Errorf("a bare :port must be shown as localhost:\n%s", stderr)
	}
	if !strings.Contains(stderr, "refreshing every 1h0m0s") {
		t.Errorf("the refresh interval is not stated:\n%s", stderr)
	}
	if !strings.Contains(stderr, "not loopback-only") {
		t.Errorf("a bind on every interface must warn:\n%s", stderr)
	}
}

func TestServeRefusesAmbiguousInputAndBadFlags(t *testing.T) {
	_, _, err := runCLI(t, "serve")
	wantErrContains(t, err, "provide exactly one input file")
	_, _, err = runCLI(t, "serve", "-refresh", "soon", "x.json")
	wantErrContains(t, err, "invalid value")
	_, _, err = runCLI(t, "serve", "-source", "ldap", "../../testdata/events.json")
	wantErrContains(t, err, `unknown source "ldap"`)
}

func TestLoadRefusesWithoutExactlyOneInput(t *testing.T) {
	_, stderr, err := runCLI(t, "load", "-db", unreachableDSN)
	wantErrContains(t, err, "exactly one input file or glob")
	if !strings.Contains(stderr, "usage: idryx load --db <dsn>") {
		t.Errorf("load usage missing:\n%s", stderr)
	}
	_, _, err = runCLI(t, "load", "-db", unreachableDSN, "a.json", "b.json")
	wantErrContains(t, err, "exactly one input file or glob")
	_, _, err = runCLI(t, "load", "-nonsense")
	wantErrContains(t, err, "flag provided but not defined")
}

func TestLoadReportsAnUnreachableDatabase(t *testing.T) {
	_, _, err := runCLI(t, "load", "-db", unreachableDSN, "../../testdata/events.json")
	wantErrContains(t, err, "ping postgres")
}

func TestRemediatePrintsEachRecommendation(t *testing.T) {
	stdout, _, err := runCLI(t, "remediate", "-source", "aws_iam", "-cloudtrail", "../../testdata/cloudtrail.json", "../../testdata/aws_iam.json")
	if err != nil {
		t.Fatalf("remediate: %v", err)
	}
	for _, want := range []string{
		"REMEDIATION (right_size) FOR: arn:aws:iam::123456789012:role/data-pipeline",
		"REMEDIATION (rotation) FOR: arn:aws:iam::123456789012:user/legacy-deploy",
		"Generated 2 remediation recommendation(s).",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in:\n%s", want, stdout)
		}
	}
}

func TestRemediateSaysSoWhenNothingNeedsChanging(t *testing.T) {
	stdout, _, err := runCLI(t, "remediate", "-source", "mcp", "../../testdata/mcp.json")
	if err != nil {
		t.Fatalf("remediate: %v", err)
	}
	if !strings.Contains(stdout, "All monitored identities are fully right-sized") {
		t.Errorf("an empty result must be said, not left blank:\n%s", stdout)
	}
	if strings.Contains(stdout, "REMEDIATION (") {
		t.Errorf("no recommendation expected:\n%s", stdout)
	}
}

func TestRemediateWritesArtifactsAndAManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	stdout, _, err := runCLI(t, "remediate", "-source", "agents", "-out", dir, "../../testdata/agents.json")
	if err != nil {
		t.Fatalf("remediate -out: %v", err)
	}
	if !strings.Contains(stdout, "Wrote 2 remediation artifact(s) and manifest.json to "+dir) {
		t.Errorf("summary line missing:\n%s", stdout)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest.json not written: %v", err)
	}
	var manifest []map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest) != 2 {
		t.Fatalf("manifest = %s (err %v), want 2 entries", data, err)
	}
}

func TestRemediateReportsAnArtifactDirectoryItCannotCreate(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "remediate", "-source", "agents", "-out", filepath.Join(blocker, "sub"), "../../testdata/agents.json")
	if err == nil {
		t.Fatal("expected an error writing under a regular file")
	}
}

// TestRemediateOpenPRRefusesANonRepository: the PR flow checks the target is
// a git work tree before it touches anything.
func TestRemediateOpenPRRefusesANonRepository(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runCLI(t, "remediate", "-source", "agents", "-open-pr", "-repo", dir, "../../testdata/agents.json")
	wantErrContains(t, err, "is not a git repository")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("the refused run wrote %d entr(ies) into the target", len(entries))
	}
}

func TestRemediateSaveDBReportsAnUnreachableDatabase(t *testing.T) {
	_, _, err := runCLI(t, "remediate", "-source", "agents", "-save-db", unreachableDSN, "../../testdata/agents.json")
	wantErrContains(t, err, "ping postgres")
}

func TestRemediateRefusesBadInput(t *testing.T) {
	_, _, err := runCLI(t, "remediate")
	wantErrContains(t, err, "provide exactly one input file")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, "remediate", "-source", "aws_iam", bad)
	wantErrContains(t, err, "parse aws_iam")
}

// stubCapture replaces the platform capture for one test.
func stubCapture(t *testing.T, fn func(context.Context, time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error)) {
	t.Helper()
	old := ebpfCaptureFunc
	ebpfCaptureFunc = fn
	t.Cleanup(func() { ebpfCaptureFunc = old })
}

// TestEBPFCaptureWritesALogTheEgressConnectorReads closes the loop the
// command promises: what ebpf-capture writes is exactly one --load egress:
// away from the rest of the pipeline.
func TestEBPFCaptureWritesALogTheEgressConnectorReads(t *testing.T) {
	when := time.Date(2026, 11, 1, 10, 0, 0, 250_000_000, time.UTC)
	var gotDuration time.Duration
	stubCapture(t, func(_ context.Context, d time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		gotDuration = d
		return []ebpfcapture.Flow{
			{Time: when, Identity: "proc:python3", Destination: "api.openai.com"},
			{Time: when.Add(time.Second), Identity: "proc:curl", Destination: "203.0.113.7"},
		}, ebpfcapture.SkippedCounts{}, nil
	})

	out := filepath.Join(t.TempDir(), "captured.json")
	_, stderr, err := runCLI(t, "ebpf-capture", "-duration", "5s", "-out", out)
	if err != nil {
		t.Fatalf("ebpf-capture: %v", err)
	}
	if gotDuration != 5*time.Second {
		t.Errorf("capture ran for %s, want the -duration 5s", gotDuration)
	}
	if !strings.Contains(stderr, "for 5s...") || !strings.Contains(stderr, "captured 2 flow(s)") {
		t.Errorf("progress lines missing:\n%s", stderr)
	}
	if strings.Contains(stderr, "not reported") || strings.Contains(stderr, "WARNING") {
		t.Errorf("nothing was skipped, so nothing may be reported as skipped:\n%s", stderr)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("capture file: %v", err)
	}
	events, rep, err := ingest.Egress(data)
	if err != nil {
		t.Fatalf("the egress connector cannot read the capture: %v", err)
	}
	if rep.Malformed != 0 || len(events) != 2 {
		t.Fatalf("egress read %d event(s), %d malformed; want 2, 0", len(events), rep.Malformed)
	}
	if events[0].IdentityID != "proc:python3" || !events[0].Time.Equal(when) {
		t.Errorf("first event = %+v, want proc:python3 at %s", events[0], when)
	}
}

func TestEBPFCaptureToStdoutStatesSkippedAndLostConnections(t *testing.T) {
	stubCapture(t, func(context.Context, time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		return nil, ebpfcapture.SkippedCounts{OtherFamily: 7, TooShort: 2, Unreadable: 1, RingbufFull: 3}, nil
	})
	stdout, stderr, err := runCLI(t, "ebpf-capture", "-duration", "0")
	if err != nil {
		t.Fatalf("ebpf-capture: %v", err)
	}
	var log ebpfcapture.EgressLog
	if err := json.Unmarshal([]byte(stdout), &log); err != nil {
		t.Fatalf("stdout is not an egress log: %v\n%s", err, stdout)
	}
	if log.Flows == nil || len(log.Flows) != 0 {
		t.Errorf("flows = %#v, want an empty (not null) list", log.Flows)
	}
	for _, want := range []string{
		"until interrupted",
		"7 connect(s) over other address families",
		"2 with an address shorter",
		"1 unreadable sockaddr(s)",
		"WARNING: 3 connection(s) were dropped because the ring buffer was full",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
}

func TestEBPFCaptureSkippedButNothingLostIsNotAWarning(t *testing.T) {
	stubCapture(t, func(context.Context, time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		return nil, ebpfcapture.SkippedCounts{OtherFamily: 4}, nil
	})
	_, stderr, err := runCLI(t, "ebpf-capture", "-duration", "1ms")
	if err != nil {
		t.Fatalf("ebpf-capture: %v", err)
	}
	if !strings.Contains(stderr, "4 connect(s) over other address families") {
		t.Errorf("skipped count missing:\n%s", stderr)
	}
	if strings.Contains(stderr, "WARNING") {
		t.Errorf("out-of-scope traffic is not lost evidence:\n%s", stderr)
	}
}

func TestEBPFCaptureReportsCaptureAndOutputFailures(t *testing.T) {
	stubCapture(t, func(context.Context, time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		return nil, ebpfcapture.SkippedCounts{}, errors.New("needs CAP_BPF")
	})
	_, _, err := runCLI(t, "ebpf-capture", "-duration", "1ms")
	wantErrContains(t, err, "needs CAP_BPF")

	stubCapture(t, func(context.Context, time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error) {
		return nil, ebpfcapture.SkippedCounts{}, nil
	})
	_, _, err = runCLI(t, "ebpf-capture", "-duration", "1ms", "-out", filepath.Join(t.TempDir(), "no", "such", "dir.json"))
	wantErrContains(t, err, "create ")
}

func TestParseSeverityAcceptsTheFourLevelsOnly(t *testing.T) {
	cases := map[string]model.Severity{
		"low":      model.SeverityLow,
		"medium":   model.SeverityMedium,
		"high":     model.SeverityHigh,
		"critical": model.SeverityCritical,
	}
	for in, want := range cases {
		got, ok := parseSeverity(in)
		if !ok || got != want {
			t.Errorf("parseSeverity(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "High", "info", "none"} {
		if got, ok := parseSeverity(bad); ok || got != model.SeverityNone {
			t.Errorf("parseSeverity(%q) = %v, %v; want none, false", bad, got, ok)
		}
	}
}

// TestParseInventoryNamesTheSourceThatFailed: a malformed inventory file is an
// error that says which connector refused it, for every inventory source.
func TestParseInventoryNamesTheSourceThatFailed(t *testing.T) {
	for _, src := range []string{"aws_iam", "gcp_iam", "azure", "agents", "mcp"} {
		_, ok, _, err := parseInventory(src, []byte("{not json"))
		if !ok {
			t.Errorf("%s: not recognised as an inventory source", src)
			continue
		}
		wantErrContains(t, err, "parse "+src+":")
	}
	if _, ok, _, err := parseInventory("okta", []byte("{}")); ok || err != nil {
		t.Errorf("okta is an event source: ok=%v err=%v, want false, nil", ok, err)
	}
}

func TestParseSourceReadsEveryEventSource(t *testing.T) {
	for _, src := range []string{"okta", "entra", "cloudtrail", "egress"} {
		if _, _, err := parseSource(src, []byte("{not json")); err == nil {
			t.Errorf("%s: malformed input accepted", src)
		}
	}
}

func TestReportPassportsSpeaksOnlyWhenSomethingWasMalformed(t *testing.T) {
	quiet := captureStderr(t, func() { reportPassports("dir", passportReport(3, 0)) })
	if quiet != "" {
		t.Errorf("a clean batch printed %q", quiet)
	}
	loud := captureStderr(t, func() { reportPassports("dir", passportReport(3, 1)) })
	if !strings.Contains(loud, "passports dir: 3 file(s) read, 1 malformed") {
		t.Errorf("malformed passports not reported: %q", loud)
	}
}

func TestClippedBoundsAndEscapesProducerText(t *testing.T) {
	long := strings.Repeat("a", maxClaimShown+10)
	got := clipped(long)
	if want := `"` + strings.Repeat("a", maxClaimShown) + `..."`; got != want {
		t.Errorf("clipped(long) = %s, want %s", got, want)
	}
	if got := clipped("evil\nidryx: forged line"); strings.Contains(got, "\n") {
		t.Errorf("a line break survived clipping: %s", got)
	}
	if got := clipped(strings.Repeat("b", maxClaimShown)); got != `"`+strings.Repeat("b", maxClaimShown)+`"` {
		t.Errorf("text exactly at the bound must not be cut: %s", got)
	}
}

func passportReport(files, malformed int) passport.Report {
	return passport.Report{Files: files, Malformed: malformed}
}

// TestFlagValuesPrintNamesNeverHeaderValues: flag.Value.String is what a
// usage or error line prints for the flag, and a header value is a
// credential, so only the names may ever appear.
func TestFlagValuesPrintNamesNeverHeaderValues(t *testing.T) {
	h := headerList{}
	for _, v := range []string{"X-Api-Key: test-key-not-real", "authorization: Bearer test-token-not-real"} {
		if err := h.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if got := h.String(); got != "Authorization,X-Api-Key" {
		t.Errorf("headerList.String() = %q, want the sorted canonical names only", got)
	}
	if got := (headerList{}).String(); got != "" {
		t.Errorf("empty headerList.String() = %q, want empty", got)
	}

	var l loadList
	for _, v := range []string{"agents:a.json", "mcp:m.json"} {
		if err := l.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if got := l.String(); got != "agents:a.json,mcp:m.json" {
		t.Errorf("loadList.String() = %q, want agents:a.json,mcp:m.json", got)
	}
}

func TestReportChainStatesAnUnreadStreamAndCapsTheBreakList(t *testing.T) {
	unread := captureStderr(t, func() { reportChain("tokenfuse", "bus/*.ndjson", tokenfuse.Chain{}) })
	if !strings.Contains(unread, "prev_hash chain NOT CHECKED") {
		t.Errorf("an unread chain must say it was not checked: %q", unread)
	}

	var breaks []tokenfuse.ChainBreak
	for i := 1; i <= maxReportedBreaks+3; i++ {
		breaks = append(breaks, tokenfuse.ChainBreak{File: "bus.ndjson", Line: i, Expected: "e", Found: "f"})
	}
	broken := captureStderr(t, func() {
		reportChain("tokenfuse", "bus.ndjson", tokenfuse.Chain{Verified: true, Breaks: breaks})
	})
	if !strings.Contains(broken, "BROKEN at 8 line(s)") {
		t.Errorf("the full break count must be stated: %q", broken)
	}
	if n := strings.Count(broken, "expected prev_hash"); n != maxReportedBreaks {
		t.Errorf("listed %d breaks, want the cap of %d", n, maxReportedBreaks)
	}
	if !strings.Contains(broken, "... and 3 more") {
		t.Errorf("the breaks beyond the cap must be counted: %q", broken)
	}
}

func TestReportStreamsCapsForeignAndUnknownListings(t *testing.T) {
	var rep tokenfuse.Report
	for i := 0; i < maxReportedBreaks+2; i++ {
		rep.Foreign = append(rep.Foreign, tokenfuse.Foreign{File: "wardryx.ndjson", Stem: "wardryx", Claimed: "tokenfuse", Count: 1, Allowed: []string{"wardryx"}})
		rep.Unknown = append(rep.Unknown, tokenfuse.UnknownFile{File: "odd.ndjson", Stem: "odd", Count: 1})
	}
	rep.ForeignSource = len(rep.Foreign)
	out := captureStderr(t, func() { reportStreams("wardryx", "bus", rep) })
	if !strings.Contains(out, "7 event(s) not ingested") {
		t.Errorf("foreign count missing: %q", out)
	}
	if n := strings.Count(out, `claims "tokenfuse"`); n != maxReportedBreaks {
		t.Errorf("listed %d foreign pairs, want %d", n, maxReportedBreaks)
	}
	if !strings.Contains(out, "... and 2 more pair(s)") || !strings.Contains(out, "... and 2 more unrecognised stream(s)") {
		t.Errorf("entries beyond the cap must be counted: %q", out)
	}
	if n := strings.Count(out, "is not a stream this build knows"); n != maxReportedBreaks {
		t.Errorf("listed %d unknown streams, want %d", n, maxReportedBreaks)
	}
}

// TestEnrichmentFilesThatCannotBeReadOrParsedFailTheRun: a usage log that is
// named and then unreadable or malformed is an error naming which one, never
// an unenriched graph that looks enriched.
func TestEnrichmentFilesThatCannotBeReadOrParsedFailTheRun(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.json")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"cloudtrail missing", []string{"-source", "aws_iam", "-cloudtrail", missing, "../../testdata/aws_iam.json"}, "read cloudtrail file"},
		{"cloudtrail malformed", []string{"-source", "aws_iam", "-cloudtrail", bad, "../../testdata/aws_iam.json"}, "parse aws_iam+cloudtrail"},
		{"gcp audit missing", []string{"-source", "gcp_iam", "-gcp-audit", missing, "../../testdata/gcp_iam.json"}, "read gcp audit file"},
		{"gcp audit malformed", []string{"-source", "gcp_iam", "-gcp-audit", bad, "../../testdata/gcp_iam.json"}, "parse gcp_iam+audit"},
		{"passports with --load", []string{"-load", "agents:../../testdata/agents.json", "-passports", "["}, "load passports"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := runCLI(t, append([]string{"detect"}, c.args...)...)
			wantErrContains(t, err, c.want)
		})
	}
}

// TestEverySubcommandRefusesAnUnknownFlag: a mistyped flag is an error, not
// a run with the flag silently ignored.
func TestEverySubcommandRefusesAnUnknownFlag(t *testing.T) {
	for _, cmd := range []string{"detect", "bom", "ai-inventory", "serve", "load", "remediate", "ebpf-capture"} {
		t.Run(cmd, func(t *testing.T) {
			_, stderr, err := runCLI(t, cmd, "-no-such-flag")
			wantErrContains(t, err, "flag provided but not defined: -no-such-flag")
			if !strings.Contains(stderr, "usage: idryx "+cmd) {
				t.Errorf("no %s usage on stderr:\n%s", cmd, stderr)
			}
		})
	}
}

// TestWarnIfNonLoopbackChecksAnAddressWithNoPort: a typo that drops the port
// must not dodge the warning.
func TestWarnIfNonLoopbackChecksAnAddressWithNoPort(t *testing.T) {
	var warned, quiet strings.Builder
	warnIfNonLoopback(&warned, "dashboard.example.com")
	warnIfNonLoopback(&quiet, "localhost")
	if !strings.Contains(warned.String(), "serving on dashboard.example.com") {
		t.Errorf("no warning for a portless public name: %q", warned.String())
	}
	if quiet.Len() != 0 {
		t.Errorf("a portless localhost warned: %q", quiet.String())
	}
}
