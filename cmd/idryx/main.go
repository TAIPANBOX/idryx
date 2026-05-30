// Command idryx ingests identity logs and reports ITDR alerts, either to the
// terminal/sinks (detect) or over a read-only web dashboard (serve).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
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

detect, serve and remediate also accept --db to read from Postgres instead of a file.`)
}

// buildGraph returns an identity graph either from a Postgres snapshot (when db
// is set) or by parsing a source log file. Exactly one of db/path is used.
// ctPath is optional: when non-empty and source is "aws_iam", CloudTrail records
// are used to mark which permissions have been exercised. auditPath does the same
// for "gcp_iam" using Cloud Audit Logs.
func buildGraph(source, privileged, path, db, ctPath, auditPath string) (graph.Reader, error) {
	if db != "" {
		store, err := graph.OpenPg(context.Background(), db)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		return store.Snapshot(context.Background())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	g := graph.New(privilegedSet(privileged))

	// aws_iam + CloudTrail enrichment path.
	if source == "aws_iam" && ctPath != "" {
		ctData, err := os.ReadFile(ctPath)
		if err != nil {
			return nil, fmt.Errorf("read cloudtrail file: %w", err)
		}
		ids, err := ingest.AWSSIAMWithUsage(data, ctData)
		if err != nil {
			return nil, fmt.Errorf("parse aws_iam+cloudtrail: %w", err)
		}
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return g, nil
	}

	// gcp_iam + Cloud Audit Logs enrichment path.
	if source == "gcp_iam" && auditPath != "" {
		auditData, err := os.ReadFile(auditPath)
		if err != nil {
			return nil, fmt.Errorf("read gcp audit file: %w", err)
		}
		ids, err := ingest.GCPIAMWithUsage(data, auditData)
		if err != nil {
			return nil, fmt.Errorf("parse gcp_iam+audit: %w", err)
		}
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return g, nil
	}

	// Inventory sources (identities + permissions), not event logs; they
	// populate the graph via AddIdentity for the NHI detectors.
	if ids, ok, err := parseInventory(source, data); err != nil {
		return nil, err
	} else if ok {
		for _, id := range ids {
			g.AddIdentity(id)
		}
		return g, nil
	}

	events, err := parseSource(source, data)
	if err != nil {
		return nil, fmt.Errorf("parse %s log: %w", source, err)
	}
	for _, e := range events {
		g.AddEvent(e)
	}
	return g, nil
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
	}
	var alerts []model.Alert
	for _, d := range ds {
		alerts = append(alerts, d.Detect(g)...)
	}
	return alerts
}

// inputArg validates the file/db combination and returns the file path (empty
// when reading from db).
func inputArg(fs *flag.FlagSet, db string) (string, error) {
	switch {
	case db != "" && fs.NArg() == 0:
		return "", nil
	case db != "" && fs.NArg() > 0:
		return "", fmt.Errorf("provide either --db or a file, not both")
	case fs.NArg() == 1:
		return fs.Arg(0), nil
	default:
		fs.Usage()
		return "", fmt.Errorf("provide exactly one input file (or --db)")
	}
}

func runDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	var (
		format     = fs.String("format", "human", "output format: human|json")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents")
		slackURL   = fs.String("slack", "", "Slack incoming-webhook URL to send alerts to")
		webhookURL = fs.String("webhook", "", "generic JSON webhook URL to send alerts to (SIEM/SOAR)")
		minSev     = fs.String("min-severity", "high", "minimum severity to deliver to sinks: low|medium|high|critical")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
	)
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx detect [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath)
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
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
	)
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx serve [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath)
	if err != nil {
		return err
	}
	alerts := runDetectors(g)

	srv := server.New(g, alerts)
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
		source     = fs.String("source", "okta", "source: okta|entra|cloudtrail|egress|aws_iam|gcp_iam|azure|agents")
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
		source     = fs.String("source", "aws_iam", "source: aws_iam|gcp_iam|azure|agents")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		ctPath     = fs.String("cloudtrail", "", "CloudTrail log to enrich aws_iam permission usage (only with --source aws_iam)")
		auditPath  = fs.String("gcp-audit", "", "Cloud Audit Log to enrich gcp_iam permission usage (only with --source gcp_iam)")
	)
	db := fs.String("db", "", "Postgres DSN to read the graph from instead of a file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx remediate [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := inputArg(fs, *db)
	if err != nil {
		return err
	}

	g, err := buildGraph(*source, *privileged, path, *db, *ctPath, *auditPath)
	if err != nil {
		return err
	}

	var count int
	for _, id := range g.Identities() {
		if rem := remediation.Generate(*id); rem != nil {
			fmt.Printf("================================================================================\n")
			fmt.Printf("REMEDIATION RECOMMENDATION FOR: %s\n", rem.IdentityID)
			fmt.Printf("EXPLANATION: %s\n", rem.Explanation)
			fmt.Printf("--------------------------------------------------------------------------------\n")
			fmt.Printf("%s\n", rem.Code)
			fmt.Printf("================================================================================\n\n")
			count++
		}
	}

	if count == 0 {
		fmt.Println("All monitored identities are fully right-sized. No unused permissions observed.")
	} else {
		fmt.Printf("Generated %d remediation recommendation(s).\n", count)
	}

	return nil
}
