// Command idryx ingests identity logs and reports ITDR alerts, either to the
// terminal/sinks (detect) or over a read-only web dashboard (serve).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/detect"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/remediation"
	"github.com/TAIPANBOX/idryx/internal/report"
	"github.com/TAIPANBOX/idryx/internal/server"
	"github.com/TAIPANBOX/idryx/internal/sink"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "idryx:", err)
		os.Exit(1)
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
	case "serve":
		return runServe(args[1:])
	case "load":
		return runLoad(args[1:])
	case "remediate":
		return runRemediate(args[1:])
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
  detect     ingest a log, run detectors, print/deliver alerts
  serve      ingest a log and serve a read-only web dashboard
  load       ingest a log into a Postgres graph (--db)
  remediate  generate Terraform right-sizing snippets for unused permissions
  version    print version

detect, serve and remediate also accept --db to read from Postgres, or one or
more --load source:path to stitch several sources into one graph (needed for
cross-layer detectors like agent_shadow_tool, which spans agents + mcp).`)
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

// buildGraph returns an identity graph from one of: a Postgres snapshot (db set),
// several stitched sources (loads set), or a single source file. Exactly one of
// the three is used, in that precedence.
func buildGraph(source, privileged, path, db, ctPath, auditPath string, loads loadList) (graph.Reader, error) {
	if db != "" {
		store, err := graph.OpenPg(context.Background(), db)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		return store.Snapshot(context.Background())
	}

	g := graph.New(privilegedSet(privileged))

	// Multi-source: stitch every --load into one graph. Cross-layer detectors
	// (e.g. agent_shadow_tool, which needs agents + mcp) only fire here.
	if len(loads) > 0 {
		for _, spec := range loads {
			if err := populate(g, spec); err != nil {
				return nil, err
			}
		}
		return g, nil
	}

	// Single source.
	if err := populate(g, loadSpec{Source: source, Path: path, CTPath: ctPath, AuditPath: auditPath}); err != nil {
		return nil, err
	}
	return g, nil
}

// populate ingests one source spec into g. Inventory sources add identities;
// event sources add events; aws_iam/gcp_iam optionally fold in usage enrichment.
func populate(g *graph.Store, spec loadSpec) error {
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
	if ids, ok, err := parseInventory(spec.Source, data); err != nil {
		return err
	} else if ok {
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return nil
	}

	// Event sources.
	events, err := parseSource(spec.Source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", spec.Source, err)
	}
	for _, e := range events {
		g.AddEvent(e)
	}
	return nil
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
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp")
		slackURL   = fs.String("slack", "", "Slack incoming-webhook URL to send alerts to")
		webhookURL = fs.String("webhook", "", "generic JSON webhook URL to send alerts to (SIEM/SOAR)")
		minSev     = fs.String("min-severity", "high", "minimum severity to deliver to sinks: low|medium|high|critical")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable (e.g. --load agents:a.json --load mcp:m.json)")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx detect [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db, loads)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, loads)
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
	var sinks []sink.Sink
	if *slackURL != "" {
		sinks = append(sinks, sink.NewSlack(*slackURL, threshold))
	}
	if *webhookURL != "" {
		sinks = append(sinks, sink.NewWebhook(*webhookURL, threshold))
	}
	for _, s := range sinks {
		if err := s.Send(alerts); err != nil {
			fmt.Fprintf(os.Stderr, "idryx: sink %s: %v\n", s.Name(), err)
		}
	}
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		addr       = fs.String("addr", ":8080", "address to listen on")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
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

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, loads)
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

	shown := *addr
	if strings.HasPrefix(shown, ":") {
		shown = "localhost" + shown
	}
	fmt.Fprintf(os.Stderr, "idryx: serving dashboard on http://%s (%d alerts)\n", shown, len(alerts))
	return http.ListenAndServe(*addr, srv.Handler())
}

func runLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	var (
		db         = fs.String("db", "", "Postgres DSN (required)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents|mcp")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
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
		return fmt.Errorf("load requires exactly one input file")
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}

	store, err := graph.OpenPg(context.Background(), *db)
	if err != nil {
		return err
	}
	defer store.Close()

	if ids, isInventory, err := parseInventory(*source, data); isInventory {
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
		return nil
	}

	events, err := parseSource(*source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", *source, err)
	}

	if err := store.Ingest(context.Background(), events, privilegedSet(*privileged)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "idryx: ingested %d events into postgres\n", len(events))
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
// bool reports whether source was an inventory source at all.
func parseInventory(source string, data []byte) ([]model.Identity, bool, error) {
	switch source {
	case "aws_iam":
		ids, err := ingest.AWSIAM(data)
		return ids, true, wrapParse(source, err)
	case "gcp_iam":
		ids, err := ingest.GCPIAM(data)
		return ids, true, wrapParse(source, err)
	case "azure":
		ids, err := ingest.Azure(data)
		return ids, true, wrapParse(source, err)
	case "agents":
		ids, err := ingest.Agents(data)
		return ids, true, wrapParse(source, err)
	case "mcp":
		ids, err := ingest.MCP(data)
		return ids, true, wrapParse(source, err)
	default:
		return nil, false, nil
	}
}

func wrapParse(source string, err error) error {
	if err != nil {
		return fmt.Errorf("parse %s: %w", source, err)
	}
	return nil
}

func parseSource(source string, data []byte) ([]model.Event, error) {
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
		return nil, fmt.Errorf("unknown source %q", source)
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
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
	)
	var loads loadList
	fs.Var(&loads, "load", "source:path to stitch into one graph; repeatable")
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	outDir := fs.String("out", "", "write apply-ready Terraform artifacts to this directory instead of stdout")
	saveDB := fs.String("save-db", "", "Postgres DSN to persist the generated recommendations into")
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

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath, loads)
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

// artifactEntry indexes one written remediation file in manifest.json.
type artifactEntry struct {
	Identity    string `json:"identity"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	Explanation string `json:"explanation"`
}

// writeRemediationArtifacts writes each recommendation as an apply-ready
// Terraform file plus a manifest.json index. idryx stays read-only on the cloud:
// it emits files to review and apply, it never mutates the provider itself.
func writeRemediationArtifacts(dir string, recs []*remediation.Recommendation) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	manifest := make([]artifactEntry, 0, len(recs))
	used := map[string]bool{}
	for _, rem := range recs {
		name := fmt.Sprintf("%s__%s.tf", rem.Kind, sanitizeName(rem.IdentityID))
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s__%s_%d.tf", rem.Kind, sanitizeName(rem.IdentityID), n)
		}
		used[name] = true
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rem.Code+"\n"), 0o644); err != nil {
			return err
		}
		manifest = append(manifest, artifactEntry{
			Identity:    rem.IdentityID,
			Kind:        rem.Kind,
			File:        name,
			Explanation: rem.Explanation,
		})
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("Wrote %d remediation artifact(s) and manifest.json to %s\n", len(recs), dir)
	return nil
}

// sanitizeName makes an identity ID safe to use as a filename segment.
func sanitizeName(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, id)
}
