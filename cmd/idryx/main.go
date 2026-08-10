// Command idryx ingests identity logs and reports ITDR alerts, either to the
// terminal/sinks (detect) or over a read-only web dashboard (serve).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TAIPANBOX/idryx/internal/bom"
	"github.com/TAIPANBOX/idryx/internal/detect"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/enforce"
	"github.com/TAIPANBOX/idryx/internal/events"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/ingest/passport"
	"github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/remediation"
	"github.com/TAIPANBOX/idryx/internal/report"
	"github.com/TAIPANBOX/idryx/internal/server"
	"github.com/TAIPANBOX/idryx/internal/sink"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// errSinkDelivery marks a runDetect error caused by one or more configured
// alert sinks (--slack/--webhook/OTLP) failing to deliver, as opposed to a
// setup/input error (bad flags, an unreadable file, a graph that failed to
// build). Detection and rendering (report.Human/report.JSON) already ran and
// are unaffected; this only marks delivery as having failed. main() maps it
// to its own exit code (exitSinkDelivery) so a cron/CI caller can tell "the
// scan ran and alerts existed but did not reach their destination" apart
// from "the invocation itself was broken" by checking $?, without scraping
// stderr text.
var errSinkDelivery = errors.New("one or more alert sinks failed to deliver")

// exitSinkDelivery is the process exit code for errSinkDelivery.
//
// idryx has exactly one other meaningful exit code today: 1, for any other
// error (see main() below) -- there is no --fail-on flag and no
// findings-threshold exit code in this repo to collide with (that is a
// tokenfuse/mcp-scan feature; idryx has never had one), and no existing use
// of 2 either.
//
// This picks 3, not 2, on purpose: idryx's sibling tokenfuse uses 1 for
// "findings met --fail-on's threshold" and 2 for "a bad --fail-on value" in
// its own mcp-scan command (crates/gateway/src/main.rs). idryx has no such
// flag today, but if it ever grows one that mirrors that convention, this
// choice leaves both of tokenfuse's codes free for it to reuse verbatim,
// rather than a sink-delivery failure quietly squatting on either meaning
// first.
const exitSinkDelivery = 3

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "idryx:", err)
		code := 1
		if errors.Is(err, errSinkDelivery) {
			code = exitSinkDelivery
		}
		os.Exit(code)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	switch args[0] {
	case "detect":
		return runDetect(args[1:])
	case "bom":
		return runBom(args[1:])
	case "serve":
		return runServe(args[1:])
	case "load":
		return runLoad(args[1:])
	case "remediate":
		return runRemediate(args[1:])
	case "ebpf-capture":
		return runEBPFCapture(args[1:])
	case "version":
		fmt.Println("idryx", version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: idryx <command> [flags] <log.json>

commands:
  detect        ingest a log, run detectors, print/deliver alerts
  bom           ingest a log, emit an Agent Bill of Materials (CycloneDX JSON)
  serve         ingest a log and serve a read-only web dashboard
  load          ingest a log into a Postgres graph (--db)
  remediate     generate Terraform right-sizing snippets for unused permissions
  ebpf-capture  capture live outbound connections via eBPF, write an egress log (Linux, root, see SECURITY.md)
  version       print version

detect, bom, serve and remediate also accept --db to read from Postgres, or
one or more --load source:path to stitch several sources into one graph
(needed for cross-layer detectors like agent_shadow_tool, which spans
agents + mcp). ebpf-capture's own output is exactly one more --load
egress:<path> away from the same detect/bom/serve/load/remediate pipeline
every other source uses.`)
}

// loadSpec is one source to ingest into the graph: a source kind and the file
// that provides it. ctPath/auditPath optionally enrich aws_iam/gcp_iam with
// observed permission usage.
type loadSpec struct {
	Source    string
	Path      string
	CTPath    string
	AuditPath string
}

// loadList collects repeated --load source:path flags so several sources can be
// stitched into one graph (e.g. agents + mcp, which the agent_shadow_tool
// detector needs together). It implements flag.Value.
type loadList []loadSpec

func (l *loadList) String() string {
	parts := make([]string, 0, len(*l))
	for _, s := range *l {
		parts = append(parts, s.Source+":"+s.Path)
	}
	return strings.Join(parts, ",")
}

func (l *loadList) Set(v string) error {
	src, path, ok := strings.Cut(v, ":")
	if !ok || src == "" || path == "" {
		return fmt.Errorf("--load expects source:path, got %q", v)
	}
	*l = append(*l, loadSpec{Source: src, Path: path})
	return nil
}

// headerList collects repeated --webhook-header "Name: Value" flags. Almost
// every real destination for an alert wants a credential, and a flag is where
// an operator supplies one: idryx never stores it and never reads it back.
type headerList map[string]string

func (h headerList) String() string {
	parts := make([]string, 0, len(h))
	for k := range h {
		parts = append(parts, k)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (h headerList) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if !ok || name == "" || value == "" {
		return fmt.Errorf("--webhook-header expects \"Name: Value\", got %q", v)
	}
	h[name] = value
	return nil
}

// usageEnrichment pairs a usage-log flag with the inventory source it can
// enrich. --cloudtrail marks which AWS permissions were actually exercised,
// --gcp-audit does the same for GCP roles; both are read at ingest time by
// the connector that owns that source, so neither means anything without it.
var usageEnrichment = []struct {
	flag   string // the CLI flag, for the error message
	source string // the --source/--load name it enriches
}{
	{"--cloudtrail", "aws_iam"},
	{"--gcp-audit", "gcp_iam"},
}

// checkUsageFlags refuses a usage-log flag that has nothing to enrich in this
// run, naming the combination.
//
// Applying the flag is the fix wherever it can apply, and buildGraph now does
// that for --load (where the paths were silently dropped) as well as for a
// single --source. But there are runs where it cannot apply at all: no
// aws_iam/gcp_iam source anywhere, or --db, where the graph comes from the
// database and enrichment already happened (or did not) at `idryx load` time.
// Accepting a documented flag and doing nothing with it is the defect this
// function exists to end, so those runs get an error rather than output that
// looks the same either way.
func checkUsageFlags(source, db, ctPath, auditPath string, loads loadList) error {
	present := map[string]bool{}
	if len(loads) > 0 {
		for _, spec := range loads {
			present[spec.Source] = true
		}
	} else if db == "" {
		present[source] = true
	}

	for _, u := range usageEnrichment {
		given := ctPath
		if u.flag == "--gcp-audit" {
			given = auditPath
		}
		if given == "" || present[u.source] {
			continue
		}
		switch {
		case db != "":
			return fmt.Errorf("%s enriches %s at ingest time and does nothing with --db: run `idryx load --db --source %s --%s ...` to persist the usage, or drop the flag",
				u.flag, u.source, u.source, strings.TrimPrefix(u.flag, "--"))
		default:
			return fmt.Errorf("%s enriches the %s source, which this run does not read: add --source %s or --load %s:<path>, or drop the flag",
				u.flag, u.source, u.source, u.source)
		}
	}
	return nil
}

// withUsagePaths returns spec with the run's usage-log paths attached when
// they apply to its source. Before this, loadList.Set populated only Source
// and Path, so every spec built from --load carried an empty CTPath/AuditPath
// and the enrichment paths in populate() were unreachable from --load mode.
func withUsagePaths(spec loadSpec, ctPath, auditPath string) loadSpec {
	if spec.Source == "aws_iam" && spec.CTPath == "" {
		spec.CTPath = ctPath
	}
	if spec.Source == "gcp_iam" && spec.AuditPath == "" {
		spec.AuditPath = auditPath
	}
	return spec
}

// buildGraph returns an identity graph from one of: a Postgres snapshot (db set),
// several stitched sources (loads set), or a single source file. Exactly one of
// the three is used, in that precedence. passports, when non-empty, is layered on
// top of whichever of the three produced the graph — a Passport document only
// enriches an identity's static metadata (owner/runtime/parent/attestation), it
// never substitutes for a behavioral or inventory source.
func buildGraph(source, privileged, path, db, ctPath, auditPath, passports string, loads loadList) (graph.Reader, error) {
	if err := checkUsageFlags(source, db, ctPath, auditPath, loads); err != nil {
		return nil, err
	}

	if db != "" {
		store, err := graph.OpenPg(context.Background(), db)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		snap, err := store.Snapshot(context.Background())
		if err != nil {
			return nil, err
		}
		// The graph arrives already populated, so the operator's privileged
		// set has to be folded in here. Without this, --privileged was
		// accepted and dropped on every --db run: it is applied at `idryx
		// load` time and nowhere else, so `detect --db --privileged
		// alice@x.com` ranked alice exactly as if she were not named, across
		// the ten detectors that raise severity for a privileged identity.
		snap.MarkPrivileged(privilegedSet(privileged))
		if err := loadPassports(snap, passports); err != nil {
			return nil, err
		}
		return snap, nil
	}

	g := graph.New(privilegedSet(privileged))

	// Multi-source: stitch every --load into one graph. Cross-layer detectors
	// (e.g. agent_shadow_tool, which needs agents + mcp) only fire here.
	if len(loads) > 0 {
		for _, spec := range loads {
			if err := populate(g, withUsagePaths(spec, ctPath, auditPath)); err != nil {
				return nil, err
			}
		}
		if err := loadPassports(g, passports); err != nil {
			return nil, err
		}
		return g, nil
	}

	// Single source.
	if err := populate(g, loadSpec{Source: source, Path: path, CTPath: ctPath, AuditPath: auditPath}); err != nil {
		return nil, err
	}
	if err := loadPassports(g, passports); err != nil {
		return nil, err
	}
	return g, nil
}

// loadPassports reads every Agent Passport document under dirOrGlob (a
// directory or glob, per the passport package) and merges each into g via
// AddIdentity — the same enrichment path aws_iam/gcp_iam usage data takes.
// A no-op when dirOrGlob is empty (the flag was not set).
func loadPassports(g *graph.Store, dirOrGlob string) error {
	if dirOrGlob == "" {
		return nil
	}
	ids, rep, err := passport.Load(dirOrGlob)
	if err != nil {
		return fmt.Errorf("load passports: %w", err)
	}
	for _, id := range ids {
		g.AddIdentity(id)
	}
	reportPassports(dirOrGlob, rep)
	return nil
}

// reportPassports prints a one-line stderr summary when a passport batch had
// any malformed files, mirroring reportTokenFuse.
func reportPassports(dirOrGlob string, rep passport.Report) {
	if rep.Malformed == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "idryx: passports %s: %d file(s) read, %d malformed\n",
		dirOrGlob, rep.Files, rep.Malformed)
}

// agentBusSources is the set of --source/--load names that share the
// agent-event bus envelope (agent-passport SPEC §6.3) and therefore the
// same tokenfuse.Load connector: TokenFuse, Wardryx, Mockryx and Verdryx
// all write the same taipanbox.dev/agent-event envelope, and Parse/Load
// derive each identity's and event's Source from the envelope's own
// `source` field, never from this map's key (see tokenfuse.go's package
// doc). A file is always attributed to its true producer, regardless of
// which of these four names picked the loader.
var agentBusSources = map[string]bool{
	"tokenfuse": true,
	"wardryx":   true,
	"mockryx":   true,
	"verdryx":   true,
	"scopyx":    true,
}

// populate ingests one source spec into g. Inventory sources add identities;
// event sources add events; aws_iam/gcp_iam optionally fold in usage enrichment.
func populate(g *graph.Store, spec loadSpec) error {
	// tokenfuse, wardryx, mockryx and verdryx are hybrid sources on the
	// shared agent-event bus (agent-passport SPEC §6.3): each produces both
	// identities and behavioral events from the same NDJSON envelopes, and
	// spec.Path may be a glob rather than a single file, so they are all
	// special-cased before the generic os.ReadFile below, ahead of the
	// inventory/event dispatch further down.
	if agentBusSources[spec.Source] {
		ids, events, rep, err := tokenfuse.Load(spec.Path)
		if err != nil {
			return fmt.Errorf("parse %s: %w", spec.Source, err)
		}
		for _, id := range ids {
			g.AddIdentity(id)
		}
		for _, e := range events {
			g.AddEvent(e)
		}
		reportTokenFuse(spec.Source, spec.Path, rep)
		return nil
	}

	data, err := os.ReadFile(spec.Path)
	if err != nil {
		return err
	}

	// aws_iam + CloudTrail enrichment path.
	if spec.Source == "aws_iam" && spec.CTPath != "" {
		ctData, err := os.ReadFile(spec.CTPath)
		if err != nil {
			return fmt.Errorf("read cloudtrail file: %w", err)
		}
		ids, err := ingest.AWSSIAMWithUsage(data, ctData)
		if err != nil {
			return fmt.Errorf("parse aws_iam+cloudtrail: %w", err)
		}
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return nil
	}

	// gcp_iam + Cloud Audit Logs enrichment path.
	if spec.Source == "gcp_iam" && spec.AuditPath != "" {
		auditData, err := os.ReadFile(spec.AuditPath)
		if err != nil {
			return fmt.Errorf("read gcp audit file: %w", err)
		}
		ids, err := ingest.GCPIAMWithUsage(data, auditData)
		if err != nil {
			return fmt.Errorf("parse gcp_iam+audit: %w", err)
		}
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return nil
	}

	// Inventory sources (identities + permissions).
	if ids, ok, rep, err := parseInventory(spec.Source, data); err != nil {
		return err
	} else if ok {
		for _, id := range ids {
			g.AddIdentity(id)
		}
		reportIngest(spec.Source, spec.Path, rep)
		return nil
	}

	// Event sources.
	events, rep, err := parseSource(spec.Source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", spec.Source, err)
	}
	for _, e := range events {
		g.AddEvent(e)
	}
	reportIngest(spec.Source, spec.Path, rep)
	return nil
}

// reportTokenFuse prints a one-line stderr summary when an agent-event-bus
// batch (tokenfuse, wardryx, mockryx, verdryx: see agentBusSources) had
// anything worth flagging (agent-passport SPEC §6.1/§7: unknown fields and
// types are tolerated, never errors, but they are still worth surfacing),
// followed by the verdict on the stream's prev_hash integrity chain.
// source is the --source/--load name that selected the loader (for the
// message only; it plays no part in identity/event attribution, which
// comes from each envelope's own `source` field).
func reportTokenFuse(source, pathOrGlob string, rep tokenfuse.Report) {
	if rep.Malformed > 0 || len(rep.UnknownTypes) > 0 {
		fmt.Fprintf(os.Stderr, "idryx: %s %s: %d line(s) read, %d malformed, %d unknown event type(s)\n",
			source, pathOrGlob, rep.Lines, rep.Malformed, len(rep.UnknownTypes))
	}
	reportChain(source, pathOrGlob, rep.Chain)
}

// maxReportedBreaks caps how many individual chain breaks are listed. One
// edit near the start of a stream breaks every line after it, so an
// uncapped list is a wall of stderr that buries the first and most useful
// line number. The count is always stated in full.
const maxReportedBreaks = 5

// reportChain states, on every agent-event-bus ingest, what the SPEC §6.5
// prev_hash chain says about the stream. It prints in all four cases on
// purpose, including the good one: an operator has to be able to tell "the
// log was intact" from "nobody checked", and before this fix both were the
// same silence.
//
// A break is reported, never fatal. This is a deliberate choice and the
// reasoning belongs beside it: idryx is a detection tool whose value is
// noticing tampering, and refusing to ingest a stream that shows evidence of
// tampering would let an attacker delete every finding in a file by editing
// one line of it. The events are still evidence; the chain says they may not
// be all of it, or not as written. That is a finding to surface loudly, not
// a reason to go quiet. It also matches the connector's existing contract
// (SPEC §6.1/§7, and the malformed-line handling above): a content problem
// is counted and reported, never a reason to abort the file.
func reportChain(source, pathOrGlob string, c tokenfuse.Chain) {
	switch {
	case !c.Verified:
		fmt.Fprintf(os.Stderr, "idryx: %s %s: prev_hash chain NOT CHECKED (the stream could not be read through), so nothing here says whether it was tampered with\n",
			source, pathOrGlob)
	case len(c.Breaks) > 0:
		fmt.Fprintf(os.Stderr, "idryx: %s %s: prev_hash chain BROKEN at %d line(s); the events were still ingested, and the log is no longer evidence of its own completeness\n",
			source, pathOrGlob, len(c.Breaks))
		for i, b := range c.Breaks {
			if i == maxReportedBreaks {
				fmt.Fprintf(os.Stderr, "idryx:   ... and %d more\n", len(c.Breaks)-maxReportedBreaks)
				break
			}
			fmt.Fprintf(os.Stderr, "idryx:   %s line %d: expected prev_hash %s, found %s\n",
				b.File, b.Line, b.Expected, b.Found)
		}
	case !c.Present():
		fmt.Fprintf(os.Stderr, "idryx: %s %s: no prev_hash chain present (SPEC 6.5 keeps it optional), so this ingest is not evidence for or against tampering\n",
			source, pathOrGlob)
	default:
		fmt.Fprintf(os.Stderr, "idryx: %s %s: prev_hash chain intact: %d event(s) chained, %d chain head(s), %d unverifiable\n",
			source, pathOrGlob, c.Chained, c.Heads, len(c.Unverifiable))
	}
}

// reportIngest prints a one-line stderr summary when an okta/entra/
// cloudtrail/egress/agents batch (see parseSource/parseInventory) had any
// malformed record -- a timestamp that does not parse as RFC3339 for the
// four event sources, or, for agents, a non-empty "created" that doesn't --
// mirroring reportTokenFuse/reportPassports. Before this, all five `continue`d
// past a bad record with nothing anywhere saying how many were skipped: for
// an identity plane, a silently truncated log is a detection gap nobody can
// see.
func reportIngest(source, path string, rep ingest.Report) {
	if rep.Malformed == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "idryx: %s %s: %d record(s) read, %d malformed\n",
		source, path, rep.Records, rep.Malformed)
}

// runDetectors runs all detectors over the graph and returns their alerts.
func runDetectors(g graph.Reader) []model.Alert {
	ds := []detect.Detector{
		detectors.NewImpossibleTravel(),
		detectors.NewMFAFatigue(),
		detectors.NewNewDevice(),
		detectors.NewBehaviorAnomaly(),
		detectors.NewStaleNHI(),
		detectors.NewOverPrivilegedNHI(),
		detectors.NewOrphanedNHI(),
		detectors.NewExcessiveAgency(),
		detectors.NewShadowAI(),
		detectors.NewLeastPrivilege(),
		detectors.NewPrivilegeEscalation(),
		detectors.NewSharedCredential(),
		detectors.NewShadowMCP(),
		detectors.NewAgentShadowTool(),
		detectors.NewRunawayAgent(),
		detectors.NewAttestationMissing(),
		detectors.NewBOMIncomplete(),
		detectors.NewDataExfiltration(),
		detectors.NewTaintedAgent(),
		detectors.NewMCPDrift(),
		detectors.NewUnmanagedEgress(),
		detectors.NewBeaconing(),
		detectors.NewClaimedAgentUnknown(),
		detectors.NewClaimedAgentDrift(),
		detectors.NewUndeclaredLLM(),
		detectors.NewUnroutedEgress(),
		detectors.NewClaimedAgentUnattested(),
	}
	var alerts []model.Alert
	for _, d := range ds {
		alerts = append(alerts, d.Detect(g)...)
	}
	return alerts
}

// inputArg validates the input combination and returns the positional file path.
// Exactly one of: --db, one or more --load, or a single positional file.
func inputArg(fs *flag.FlagSet, db string, loads loadList) (string, error) {
	if len(loads) > 0 {
		if db != "" || fs.NArg() > 0 {
			return "", fmt.Errorf("use --load on its own, not with --db or a positional file")
		}
		return "", nil
	}
	switch {
	case db != "" && fs.NArg() == 0:
		return "", nil
	case db != "" && fs.NArg() > 0:
		return "", fmt.Errorf("provide either --db or a file, not both")
	case fs.NArg() == 1:
		return fs.Arg(0), nil
	default:
		fs.Usage()
		return "", fmt.Errorf("provide exactly one input file, --db, or --load source:path")
	}
}

func runDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	var (
		format     = fs.String("format", "human", "output format: human|json")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp|tokenfuse|wardryx|mockryx|verdryx|scopyx")
		slackURL   = fs.String("slack", "", "Slack incoming-webhook URL to send alerts to")
		webhookURL = fs.String("webhook", "", "generic JSON webhook URL to send alerts to (SIEM/SOAR)")
		webhookHdr = headerList{}
		minSev     = fs.String("min-severity", "high", "minimum severity to deliver to sinks: low|medium|high|critical")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (with --source aws_iam or --load aws_iam:<path>; an error when the run reads neither)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (with --source gcp_iam or --load gcp_iam:<path>; an error when the run reads neither)")
		passports  = fs.String("passports", "", "directory or glob of agent-passport JSON documents to enrich agent identities (owner/runtime/parent/attestation)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable (e.g. --load agents:a.json --load mcp:m.json)")
	fs.Var(webhookHdr, "webhook-header", "\"Name: Value\" header for --webhook; repeatable (e.g. --webhook-header \"Authorization: Bearer KEY\")")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx detect [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nenv:\n  IDRYX_OTLP_ENDPOINT  OTLP/HTTP collector endpoint to deliver alerts to as trace spans (e.g. http://localhost:4318); unset disables the sink\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db, loads)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, *passports, loads)
	if err != nil {
		return err
	}
	alerts := runDetectors(g)

	switch *format {
	case "human":
		report.Human(os.Stdout, alerts)
	case "json":
		if err := report.JSON(os.Stdout, alerts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}

	threshold, ok := parseSeverity(*minSev)
	if !ok {
		return fmt.Errorf("invalid --min-severity %q", *minSev)
	}
	// One run identifier per invocation, minted here so every destination
	// labels the same scan the same way.
	//
	// Required rather than optional: trailryx refuses an event with no run_id
	// rather than inventing one, because a fabricated run puts unrelated
	// events together and a reconstruction of that run reports them as
	// related. A scan is the unit an operator repeats, so it is the unit.
	runID := fmt.Sprintf("idryx-%d", time.Now().UTC().Unix())

	var sinks []sink.Sink
	if *slackURL != "" {
		sinks = append(sinks, sink.NewSlack(*slackURL, threshold))
	}
	if *webhookURL != "" {
		sinks = append(sinks, sink.NewWebhook(*webhookURL, threshold, webhookHdr))
	}
	// OTLP has no --otlp flag: IDRYX_OTLP_ENDPOINT is the only switch. A
	// collector endpoint is typically already environment-configured for
	// every other service in a deployment, so it does not need its own
	// per-invocation flag. Unset means disabled, exactly like --slack/
	// --webhook being empty: zero behavior change for anyone not using it.
	if endpoint := os.Getenv("IDRYX_OTLP_ENDPOINT"); endpoint != "" {
		sinks = append(sinks, sink.NewOTLP(endpoint, threshold))
	}
	// The shared agent-event bus, which is what heraldyx and trailryx read.
	//
	// No flag, for the reason OTLP has none: a deployment that runs this stack
	// already has one events directory that every plane writes into, so the
	// path is environment configuration rather than a per-invocation choice.
	// Unset means disabled, exactly like the other three being empty.
	//
	// It takes NO severity threshold, unlike the three above. They page a
	// person and filter for that reason; this is a record, and a record
	// filtered by severity answers "what happened" with "the parts somebody
	// thought were interesting". heraldyx applies the threshold at the other
	// end, where the reader is.
	if path := os.Getenv("IDRYX_EVENTS"); path != "" {
		// The operator's own trust domain. Required WITH the path rather than
		// optional beside it: idryx inventories identities under its own ids
		// (`agent:ops-helper`), the envelope wants
		// `agent://<trust-domain>/<name>`, and only the operator can say the
		// domain. Configuring the path and not the domain would produce a
		// journal that is created, opened, and forever empty, which reads as "no
		// findings" and is "not finished being configured".
		domain := os.Getenv("IDRYX_TRUST_DOMAIN")
		if domain == "" {
			return fmt.Errorf("IDRYX_EVENTS is set and IDRYX_TRUST_DOMAIN is not. " +
				"The event envelope needs agent://<trust-domain>/<name> and only you can say " +
				"the domain; inventing one would put every agent here under a name nobody chose. " +
				"Set IDRYX_TRUST_DOMAIN=acme.example, or unset IDRYX_EVENTS")
		}
		bus, err := events.New(path, runID, domain)
		if err != nil {
			return err
		}
		if bus != nil {
			defer func() {
				if skipped, claimed, failed := bus.Counts(); skipped > 0 || claimed > 0 || failed > 0 {
					// Said out loud rather than kept inside. On an estate whose
					// identities are mostly service accounts the skip count will
					// be most of them, which is correct and is exactly the number
					// somebody reading "12 findings, 2 events" needs to see.
					//
					// The claimed count is separated because it is a different
					// fact about the estate, not a smaller version of the same
					// one: those findings rest on what a process said about
					// itself. It was a count of what could NOT be written until
					// 2026-08-10, when the envelope grew a way to carry the
					// distinction; it is now a count of what WAS, under v0.3.
					// See events.WrittenClaimed.
					fmt.Fprintf(os.Stderr,
						"idryx: agent-event journal: %d finding(s) had no agent subject and were not written, "+
							"%d were written about a self-declared (claimed:) identity under schema v0.3, %d failed\n",
						skipped, claimed, failed)
				}
				if err := bus.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "idryx: closing the agent-event journal: %v\n", err)
				}
			}()
			sinks = append(sinks, bus)
		}
	}
	var failedSinks int
	for _, s := range sinks {
		if err := s.Send(alerts); err != nil {
			fmt.Fprintf(os.Stderr, "idryx: sink %s: %v\n", s.Name(), err)
			failedSinks++
		}
	}
	if failedSinks > 0 {
		// The loop above already tried every sink (no early return on the
		// first failure), so a partial failure still delivered to whichever
		// sinks worked; only the exit status reflects the failure here.
		return fmt.Errorf("%d of %d alert sink(s) failed to deliver: %w", failedSinks, len(sinks), errSinkDelivery)
	}
	return nil
}

// runBom builds the same graph detect does and renders it as an Agent Bill
// of Materials instead of alerts: a defensive governance inventory of the
// operator's own agent identities (owner/runtime/attestation/tools/
// delegation/blast radius), not a detection pass. -format defaults to json
// (the CycloneDX-shaped machine artifact is the primary output; -format
// human is for a quick terminal read). -source defaults to "agents" rather
// than detect/serve/load's "okta": only agent-type identities produce
// Agent-BOM entries, so an IdP event source alone would emit an empty BOM.
func runBom(args []string) error {
	fs := flag.NewFlagSet("bom", flag.ContinueOnError)
	var (
		format     = fs.String("format", "json", "output format: json|human")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "agents", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp|tokenfuse|wardryx|mockryx|verdryx|scopyx")
		passports  = fs.String("passports", "", "directory or glob of agent-passport JSON documents to enrich agent identities (owner/runtime/parent/attestation)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable (e.g. --load agents:a.json --load mcp:m.json)")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx bom [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db, loads)
	if err != nil {
		return err
	}

	// bom has no --cloudtrail/--gcp-audit flags: usage-enrichment data feeds
	// detectors' least_privilege/over_privileged judgments, not the static
	// inventory fields an Agent-BOM records, so it is out of scope here
	// (mirroring remediate's own precedent of narrowing buildGraph's args to
	// what the command actually consumes).
	g, err := buildGraph(*source, *privileged, path, *db, "", "", *passports, loads)
	if err != nil {
		return err
	}

	b := bom.Build(g)
	switch *format {
	case "json":
		return bom.JSON(os.Stdout, b, version)
	case "human":
		bom.Human(os.Stdout, b)
		return nil
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
}

// defaultServeAddr is the default bind address for `idryx serve`: loopback
// only. internal/server has no authentication, authorization, CORS policy or
// rate limiting on /api/alerts, /api/identities or /api/remediations --
// together the whole identity graph, every alert summary, and every
// generated remediation -- and SECURITY.md documents that gap deliberately,
// on the assumption the operator reaches it over a WireGuard/SSH tunnel.
// That is a documented constraint, not a defect; defaulting the *bind* to
// every interface made it easy to violate by accident. An operator who
// genuinely wants a wider bind passes -addr explicitly and gets
// warnIfNonLoopback's warning below.
const defaultServeAddr = "127.0.0.1:8080"

// isLoopbackHost reports whether host -- the host part of an -addr value,
// e.g. from net.SplitHostPort -- is loopback-only. An empty host (as in
// ":8080", -addr's previous default) means "every interface" to net/http, so
// it is NOT loopback. Beyond the literal 127.0.0.1, this accepts the whole
// 127.0.0.0/8 range and ::1 (net.IP.IsLoopback), plus the "localhost" name,
// mirroring the precedent in tokenfuse's control plane
// (TOKENFUSE_CLOUD_HOST, crates/cloud/src/main.rs), which checks
// "127.0.0.1" | "localhost" | "::1".
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnIfNonLoopback prints a loud, unmissable warning to w when addr's host
// is not loopback-only, mirroring the precedent in tokenfuse's control plane
// (TOKENFUSE_CLOUD_HOST: binds to loopback by default, warns loudly on a
// wider bind; see crates/cloud/src/main.rs). The dashboard's lack of auth is
// a deliberate, documented constraint (SECURITY.md), so a wider bind is
// meant to be a visible, deliberate operator choice, not a silent default.
// A malformed addr (fails SplitHostPort, e.g. a bare hostname with no port)
// is still checked against its own literal value, so a typo does not dodge
// the warning by accident.
func warnIfNonLoopback(w io.Writer, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if isLoopbackHost(host) {
		return
	}
	fmt.Fprintf(w, "idryx: warning: serving on %s, which is not loopback-only: the dashboard is now reachable from the network. SECURITY.md documents /api/alerts, /api/identities and /api/remediations as having no authentication, authorization, CORS policy or rate limiting; restrict this with a firewall or a WireGuard/SSH tunnel (the assumed deployment model), or bind to 127.0.0.1, unless this exposure is deliberate and already secured another way.\n", addr)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		addr       = fs.String("addr", defaultServeAddr, "address to listen on")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp|tokenfuse|wardryx|mockryx|verdryx|scopyx")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (with --source aws_iam or --load aws_iam:<path>; an error when the run reads neither)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (with --source gcp_iam or --load gcp_iam:<path>; an error when the run reads neither)")
		passports  = fs.String("passports", "", "directory or glob of agent-passport JSON documents to enrich agent identities (owner/runtime/parent/attestation)")
		refresh    = fs.Duration("refresh", 15*time.Second, "re-read the source and rebuild the graph every interval so a long-lived server stays live (0 disables; ignored with --db)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable (e.g. --load agents:a.json --load mcp:m.json)")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx serve [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db, loads)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, *passports, loads)
	if err != nil {
		return err
	}
	alerts := runDetectors(g)

	srv := server.New(g, alerts)

	// When backed by Postgres, serve any persisted remediations (from
	// `remediate --save-db`) instead of recomputing them from the graph.
	if *db != "" {
		store, err := graph.OpenPg(context.Background(), *db)
		if err != nil {
			return err
		}
		defer store.Close()
		recs, err := store.RemediationRecords(context.Background())
		if err != nil {
			return err
		}
		if len(recs) > 0 {
			srv.SetRemediations(recs)
			fmt.Fprintf(os.Stderr, "idryx: serving %d persisted remediation(s) from postgres\n", len(recs))
		}
	}

	// Keep the served graph live. buildGraph ran once above; without this the
	// server answers from that boot-time snapshot forever, so a dashboard fed
	// by a growing event file goes stale the instant traffic arrives and stays
	// wrong until the process restarts (an identity plane reporting "0 alerts"
	// over a file that already holds detections). Re-read on a ticker and swap
	// the rebuilt graph in atomically. File/--load mode only: --db takes a
	// one-shot Postgres snapshot with its own lifecycle and persisted
	// remediations. A rebuild that errors keeps the last good graph rather than
	// blanking the dashboard.
	if *db == "" && *refresh > 0 {
		go func() {
			t := time.NewTicker(*refresh)
			defer t.Stop()
			for range t.C {
				g2, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, *passports, loads)
				if err != nil {
					fmt.Fprintf(os.Stderr, "idryx: refresh failed, keeping the last good graph: %v\n", err)
					continue
				}
				srv.Replace(g2, runDetectors(g2))
			}
		}()
	}

	shown := *addr
	if strings.HasPrefix(shown, ":") {
		shown = "localhost" + shown
	}
	refreshNote := "static (refresh off)"
	if *db == "" && *refresh > 0 {
		refreshNote = "refreshing every " + refresh.String()
	}
	fmt.Fprintf(os.Stderr, "idryx: serving dashboard on http://%s (%d alerts, %s)\n", shown, len(alerts), refreshNote)
	warnIfNonLoopback(os.Stderr, *addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

func runLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	var (
		db         = fs.String("db", "", "Postgres DSN (required)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp|tokenfuse|wardryx|mockryx|verdryx|scopyx")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		passports  = fs.String("passports", "", "directory or glob of agent-passport JSON documents to enrich agent identities (owner/runtime/parent/attestation)")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx load --db <dsn> [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *db == "" {
		fs.Usage()
		return fmt.Errorf("load requires --db")
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("load requires exactly one input file or glob")
	}

	store, err := graph.OpenPg(context.Background(), *db)
	if err != nil {
		return err
	}
	defer store.Close()

	// tokenfuse, wardryx, mockryx and verdryx are hybrid sources on the
	// shared agent-event bus (identities + events from the same NDJSON
	// envelopes) and their path argument may be a glob, so, like populate()
	// for the file-graph path, they are all special-cased ahead of the
	// generic os.ReadFile below.
	if agentBusSources[*source] {
		ids, events, rep, err := tokenfuse.Load(fs.Arg(0))
		if err != nil {
			return err
		}
		privSet := privilegedSet(*privileged)
		for i := range ids {
			if privSet[ids[i].ID] {
				ids[i].Privileged = true
			}
		}
		if err := store.IngestIdentities(context.Background(), ids); err != nil {
			return err
		}
		if err := store.Ingest(context.Background(), events, privSet); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "idryx: ingested %d identities and %d events from %s into postgres\n", len(ids), len(events), *source)
		reportTokenFuse(*source, fs.Arg(0), rep)
		return ingestPassportsPg(store, *passports)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}

	if ids, isInventory, rep, err := parseInventory(*source, data); isInventory {
		if err != nil {
			return err
		}
		// Apply privileged flag from CLI arguments if specified
		privSet := privilegedSet(*privileged)
		for i := range ids {
			if privSet[ids[i].ID] {
				ids[i].Privileged = true
			}
		}
		if err := store.IngestIdentities(context.Background(), ids); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "idryx: ingested %d identities into postgres\n", len(ids))
		reportIngest(*source, fs.Arg(0), rep)
		return ingestPassportsPg(store, *passports)
	}

	events, rep, err := parseSource(*source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", *source, err)
	}

	if err := store.Ingest(context.Background(), events, privilegedSet(*privileged)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "idryx: ingested %d events into postgres\n", len(events))
	reportIngest(*source, fs.Arg(0), rep)
	return ingestPassportsPg(store, *passports)
}

// ingestPassportsPg loads every Agent Passport document under dirOrGlob and
// ingests each as an identity into the Postgres graph, mirroring the
// tokenfuse hybrid-source ingestion above. A no-op when dirOrGlob is empty.
func ingestPassportsPg(store *graph.PgStore, dirOrGlob string) error {
	if dirOrGlob == "" {
		return nil
	}
	ids, rep, err := passport.Load(dirOrGlob)
	if err != nil {
		return fmt.Errorf("load passports: %w", err)
	}
	if err := store.IngestIdentities(context.Background(), ids); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "idryx: ingested %d identities from passports into postgres\n", len(ids))
	reportPassports(dirOrGlob, rep)
	return nil
}

func parseSeverity(s string) (model.Severity, bool) {
	switch s {
	case "low":
		return model.SeverityLow, true
	case "medium":
		return model.SeverityMedium, true
	case "high":
		return model.SeverityHigh, true
	case "critical":
		return model.SeverityCritical, true
	default:
		return model.SeverityNone, false
	}
}

// parseInventory handles inventory sources (NHI identities, not events). The
// bool reports whether source was an inventory source at all. Only "agents"
// produces a nonzero ingest.Report today (aws_iam/gcp_iam/azure/mcp have no
// malformed-record concept of their own); the other four always return the
// zero Report, which reportIngest treats as a no-op, so this is a uniform
// return shape with no behavior change for them.
func parseInventory(source string, data []byte) ([]model.Identity, bool, ingest.Report, error) {
	switch source {
	case "aws_iam":
		ids, err := ingest.AWSIAM(data)
		return ids, true, ingest.Report{}, wrapParse(source, err)
	case "gcp_iam":
		ids, err := ingest.GCPIAM(data)
		return ids, true, ingest.Report{}, wrapParse(source, err)
	case "azure":
		ids, err := ingest.Azure(data)
		return ids, true, ingest.Report{}, wrapParse(source, err)
	case "agents":
		ids, rep, err := ingest.Agents(data)
		return ids, true, rep, wrapParse(source, err)
	case "mcp":
		ids, err := ingest.MCP(data)
		return ids, true, ingest.Report{}, wrapParse(source, err)
	default:
		return nil, false, ingest.Report{}, nil
	}
}

func wrapParse(source string, err error) error {
	if err != nil {
		return fmt.Errorf("parse %s: %w", source, err)
	}
	return nil
}

func parseSource(source string, data []byte) ([]model.Event, ingest.Report, error) {
	switch source {
	case "okta":
		return ingest.Okta(data)
	case "entra":
		return ingest.Entra(data)
	case "cloudtrail":
		return ingest.CloudTrail(data)
	case "egress":
		return ingest.Egress(data)
	default:
		return nil, ingest.Report{}, fmt.Errorf("unknown source %q", source)
	}
}

func privilegedSet(csv string) map[string]bool {
	set := make(map[string]bool)
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	return set
}

func runRemediate(args []string) error {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	var (
		source     = fs.String("source", "aws_iam", "source: aws_iam|gcp_iam|azure|agents|mcp")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (with --source aws_iam or --load aws_iam:<path>; an error when the run reads neither)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (with --source gcp_iam or --load gcp_iam:<path>; an error when the run reads neither)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	outDir := fs.String("out", "", "write proposed-diff Terraform artifacts (for review, not direct apply) to this directory instead of stdout")
	saveDB := fs.String("save-db", "", "Postgres DSN to persist the generated recommendations into")
	openPR := fs.Bool("open-pr", false, "open a GitHub PR with the remediation artifacts against --repo (needs git + gh)")
	repoDir := fs.String("repo", "", "path to the IaC git repo to open the remediation PR against")
	prBase := fs.String("pr-base", "main", "base branch for the remediation pull request")
	prSubdir := fs.String("pr-subdir", "idryx", "directory within the repo to write artifacts into")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx remediate [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db, loads)
	if err != nil {
		return err
	}

	// remediate has no --passports flag (out of scope: it consumes the
	// graph's permissions/usage, not agent identity metadata), so no
	// passport directory is layered on here.
	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, "", loads)
	if err != nil {
		return err
	}

	var recs []*remediation.Recommendation
	for _, id := range g.Identities() {
		if rem := remediation.Generate(*id); rem != nil {
			recs = append(recs, rem)
		}
		if rem := remediation.GenerateRotation(*id); rem != nil {
			recs = append(recs, rem)
		}
	}

	if *saveDB != "" {
		store, err := graph.OpenPg(context.Background(), *saveDB)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.SaveRemediations(context.Background(), recs); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "idryx: persisted %d remediation(s) to postgres\n", len(recs))
		return nil
	}

	if *openPR {
		if *repoDir == "" {
			return fmt.Errorf("--open-pr requires --repo <path to IaC repo>")
		}
		url, err := enforce.OpenPR(context.Background(), enforce.ExecRunner{}, recs, enforce.Options{
			RepoDir: *repoDir,
			SubDir:  *prSubdir,
			Base:    *prBase,
		})
		if err != nil {
			return err
		}
		fmt.Printf("Opened remediation PR: %s\n", url)
		return nil
	}

	if *outDir != "" {
		return writeRemediationArtifacts(*outDir, recs)
	}

	for _, rem := range recs {
		fmt.Printf("================================================================================\n")
		fmt.Printf("REMEDIATION (%s) FOR: %s\n", rem.Kind, rem.IdentityID)
		fmt.Printf("EXPLANATION: %s\n", rem.Explanation)
		fmt.Printf("--------------------------------------------------------------------------------\n")
		fmt.Printf("%s\n", rem.Code)
		fmt.Printf("================================================================================\n\n")
	}

	if len(recs) == 0 {
		fmt.Println("All monitored identities are fully right-sized and within credential-rotation age.")
	} else {
		fmt.Printf("Generated %d remediation recommendation(s).\n", len(recs))
	}

	return nil
}

// writeRemediationArtifacts writes the proposed-diff Terraform files (for
// review, not direct apply; see remediation.WriteArtifacts) plus a
// manifest.json via the shared remediation writer (one source of truth with the
// pull-request flow). idryx stays read-only on the cloud: it emits files to
// review and fold into your own IaC, it never mutates the provider itself.
func writeRemediationArtifacts(dir string, recs []*remediation.Recommendation) error {
	manifest, err := remediation.WriteArtifacts(dir, recs)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %d remediation artifact(s) and manifest.json to %s\n", len(manifest), dir)
	return nil
}

// ebpfCaptureFunc performs the actual capture; runEBPFCapture is the only
// caller. Exactly one of ebpf_linux.go (the real capture, via
// internal/ebpfcapture.Run) or ebpf_other.go (a clear "not supported"
// error) sets this via init(), selected by GOOS at compile time -- so this
// file needs no build tag of its own even though the real implementation is
// Linux-only.
var ebpfCaptureFunc func(ctx context.Context, duration time.Duration) ([]ebpfcapture.Flow, ebpfcapture.SkippedCounts, error)

// runEBPFCapture drives idryx's Linux-only eBPF network-behavior sensor
// (internal/ebpfcapture): capture live outbound connections and write them
// out in exactly the wire shape internal/ingest/egress.go's Egress already
// parses, so the result plugs straight into the same
// detect/bom/serve/load/remediate pipeline every other source uses, via
// --load egress:<path>.
func runEBPFCapture(args []string) error {
	fs := flag.NewFlagSet("ebpf-capture", flag.ContinueOnError)
	duration := fs.Duration("duration", 30*time.Second, "how long to capture; 0 runs until interrupted (Ctrl+C)")
	out := fs.String("out", "", "write the captured egress log here (default: stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx ebpf-capture [flags]\n\nflags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nrequires Linux, root (or CAP_BPF+CAP_PERFMON), and a BTF-enabled kernel; see SECURITY.md.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *duration > 0 {
		fmt.Fprintf(os.Stderr, "idryx: capturing outbound connections via eBPF for %s...\n", *duration)
	} else {
		fmt.Fprintln(os.Stderr, "idryx: capturing outbound connections via eBPF until interrupted (Ctrl+C)...")
	}

	flows, skipped, err := ebpfCaptureFunc(ctx, *duration)
	if err != nil {
		return err
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fmt.Errorf("create %s: %w", *out, err)
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ebpfcapture.ToEgressLog(flows)); err != nil {
		return fmt.Errorf("write egress log: %w", err)
	}
	fmt.Fprintf(os.Stderr, "idryx: captured %d flow(s)\n", len(flows))

	// What the sensor did NOT report, said out loud. AGENTS.md invariant 4:
	// idryx must say what it could not observe rather than present a partial
	// graph as a complete one, and "captured 0 flow(s)" alone cannot
	// distinguish a quiet host from a sensor watching the wrong thing.
	//
	// The two out-of-scope counters are informational; a full ring buffer is
	// not, because it means connections this sensor wanted to record were lost,
	// so it is worded as a warning and named last, where an operator reading a
	// terminal stops.
	if skipped.Any() {
		fmt.Fprintf(os.Stderr, "idryx: not reported -- %d connect(s) over other address families (AF_UNIX, netlink, ...), %d unreadable sockaddr(s)\n",
			skipped.OtherFamily, skipped.Unreadable)
	}
	if skipped.Lost() {
		fmt.Fprintf(os.Stderr, "idryx: WARNING: %d connection(s) were dropped because the ring buffer was full; this capture is incomplete\n",
			skipped.RingbufFull)
	}
	return nil
}
