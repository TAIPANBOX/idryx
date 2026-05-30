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
  detect   ingest a log, run detectors, print/deliver alerts
  serve    ingest a log and serve a read-only web dashboard
  load     ingest a log into a Postgres graph (--db)
  version  print version

detect and serve also accept --db to read from Postgres instead of a file.`)
}

// buildGraph returns an identity graph either from a Postgres snapshot (when db
// is set) or by parsing a source log file. Exactly one of db/path is used.
func buildGraph(source, privileged, path, db string) (graph.Reader, error) {
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
	events, err := parseSource(source, data)
	if err != nil {
		return nil, fmt.Errorf("parse %s log: %w", source, err)
	}
	g := graph.New(privilegedSet(privileged))
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
		source     = fs.String("source", "okta", "log source: okta|entra|cloudtrail")
		slackURL   = fs.String("slack", "", "Slack incoming-webhook URL to send alerts to")
		webhookURL = fs.String("webhook", "", "generic JSON webhook URL to send alerts to (SIEM/SOAR)")
		minSev     = fs.String("min-severity", "high", "minimum severity to deliver to sinks: low|medium|high|critical")
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

	g, err := buildGraph(*source, *privileged, path, *db)
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
		source     = fs.String("source", "okta", "log source: okta|entra|cloudtrail")
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

	g, err := buildGraph(*source, *privileged, path, *db)
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
		source     = fs.String("source", "okta", "log source: okta|entra|cloudtrail")
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
	events, err := parseSource(*source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", *source, err)
	}

	store, err := graph.OpenPg(context.Background(), *db)
	if err != nil {
		return err
	}
	defer store.Close()
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

func parseSource(source string, data []byte) ([]model.Event, error) {
	switch source {
	case "okta":
		return ingest.Okta(data)
	case "entra":
		return ingest.Entra(data)
	case "cloudtrail":
		return ingest.CloudTrail(data)
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
