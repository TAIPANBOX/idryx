// Command idryx ingests identity events and reports ITDR alerts.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/detect"
	"github.com/TAIPANBOX/idryx/internal/detect/detectors"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/ingest"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/report"
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
	fs := flag.NewFlagSet("idryx", flag.ContinueOnError)
	var (
		format     = fs.String("format", "human", "output format: human|json")
		privileged = fs.String("privileged", "", "comma-separated privileged identities (emails)")
		source     = fs.String("source", "okta", "log source: okta|entra|cloudtrail")
		slackURL   = fs.String("slack", "", "Slack incoming-webhook URL to send alerts to")
		webhookURL = fs.String("webhook", "", "generic JSON webhook URL to send alerts to (SIEM/SOAR)")
		minSev     = fs.String("min-severity", "high", "minimum severity to deliver to sinks: low|medium|high|critical")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: idryx detect [flags] <log.json>\n\nflags:\n")
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	if args[0] != "detect" {
		fs.Usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("detect requires exactly one input file")
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	events, err := parseSource(*source, data)
	if err != nil {
		return fmt.Errorf("parse %s log: %w", *source, err)
	}

	g := graph.New(privilegedSet(*privileged))
	for _, e := range events {
		g.AddEvent(e)
	}

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
