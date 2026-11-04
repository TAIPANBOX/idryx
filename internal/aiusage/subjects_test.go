package aiusage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func subjectRow(t *testing.T, r Report, subject, provider string) SubjectRow {
	t.Helper()
	for _, row := range r.Subjects {
		if row.Subject == subject && row.Provider == provider {
			return row
		}
	}
	t.Fatalf("no subject row for %q / %q; rows: %+v", subject, provider, r.Subjects)
	return SubjectRow{}
}

func sourceRow(t *testing.T, r Report, source string) SourceRow {
	t.Helper()
	for _, row := range r.Sources {
		if row.Source == source {
			return row
		}
	}
	t.Fatalf("no source row for %q; rows: %+v", source, r.Sources)
	return SourceRow{}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func timeAt(i int) time.Time { return time.Date(2026, 11, 4, 10, i, 0, 0, time.UTC) }

// portMatch is the matcher as the real vocabulary behaves: a destination may
// carry a port, and the provider is the same with or without it.
func portMatch(host string) (string, bool) { return fakeMatch(strings.SplitN(host, ":", 2)[0]) }

func passportAgent(id string, models ...model.DeclaredModel) model.Identity {
	return model.Identity{ID: id, Type: model.IdentityAgent, Source: "passport", DeclaredModels: models}
}

func TestADeclaredProviderNoSourceSawIsNamedDeclaredNotSeen(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/bot",
			model.DeclaredModel{Provider: "Anthropic", Model: "claude-sonnet-5-5"},
			model.DeclaredModel{Provider: "anthropic", Model: "claude-haiku-5-5"}))
	})
	row := subjectRow(t, Build(g, fakeMatch, nil), "agent://acme.example/bot", "anthropic")

	if row.Gap != GapDeclaredNotSeen {
		t.Errorf("gap = %q, want %q", row.Gap, GapDeclaredNotSeen)
	}
	if !row.Declared || row.Seen != SeenNone {
		t.Errorf("declared=%v seen=%q, want declared and not seen", row.Declared, row.Seen)
	}
	if want := []string{"claude-haiku-5-5", "claude-sonnet-5-5"}; !reflect.DeepEqual(row.Models, want) {
		t.Errorf("models = %v, want the declared models sorted: %v", row.Models, want)
	}
}

func TestAProviderAnAgentReachedAndNeverDeclaredIsNamedSeenNotDeclared(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/bot", model.DeclaredModel{Provider: "anthropic"}))
		g.AddEvent(egress("agent://acme.example/bot", "api.openai.com:443"))
	})
	r := Build(g, portMatch, nil)

	got := subjectRow(t, r, "agent://acme.example/bot", "openai")
	if got.Gap != GapSeenNotDeclared || got.Seen != SeenEgress || got.Declared {
		t.Errorf("openai row = %+v, want seen but not declared", got)
	}
	if !reflect.DeepEqual(got.Hosts, []string{"api.openai.com"}) {
		t.Errorf("hosts = %v, want the host the provider was reached on, without its port", got.Hosts)
	}
	if !contains(got.Via, "egress-log") || contains(got.Via, "ebpf") {
		t.Errorf("via = %v, want the egress log and not the sensor", got.Via)
	}
	if first := subjectRow(t, r, "agent://acme.example/bot", "anthropic"); first.Gap != GapDeclaredNotSeen || first.Seen != SeenNone {
		t.Errorf("the declared provider nobody reached = %+v, want declared but not seen", first)
	}
}

func TestAProcessSeenReachingAProviderIsNamedSeenWithNoDeclarationAndAttributedByName(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddEvent(egress("proc:curl@cg7", "api.openai.com:443"))
		g.AddEvent(egress("claimed:agent://evil.example/x", "api.anthropic.com:443"))
	})
	r := Build(g, portMatch, nil)

	proc := subjectRow(t, r, "proc:curl@cg7", "openai")
	if proc.Gap != GapSeenNoDeclaration || proc.Kind != "process" || proc.Attribution != "process name" || !contains(proc.Via, "ebpf") {
		t.Errorf("process row = %+v, want seen with no declaration, kind process, attributed by process name, via ebpf", proc)
	}
	claimed := subjectRow(t, r, "claimed:agent://evil.example/x", "anthropic")
	if claimed.Gap != GapSeenNoDeclaration || claimed.Attribution != "self-declared" || !contains(claimed.Via, "ebpf") {
		t.Errorf("claimed row = %+v, want seen with no declaration and a self-declared attribution", claimed)
	}
}

func TestAnAgentActiveOnTheBusIsNotCalledUnseenAndTheBusNamesNoProvider(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/bot", model.DeclaredModel{Provider: "anthropic"}))
		for i := 0; i < 3; i++ {
			g.AddEvent(model.Event{IdentityID: "agent://acme.example/bot", Type: model.EventSpendSpike, Source: "tokenfuse", Time: timeAt(i)})
		}
	})
	r := Build(g, fakeMatch, nil)
	row := subjectRow(t, r, "agent://acme.example/bot", "anthropic")

	if row.Gap != GapDeclaredBusOnly || row.Seen != SeenBusOnly {
		t.Errorf("row = %+v, want declared and active on the bus only", row)
	}
	if !reflect.DeepEqual(row.Bus, []BusCount{{Source: "tokenfuse", Events: 3}}) {
		t.Errorf("bus = %+v, want tokenfuse with 3 events", row.Bus)
	}
	if !strings.Contains(strings.Join(r.Limits, " "), "bus names no provider") {
		t.Errorf("limits never say the bus names no provider: %v", r.Limits)
	}

	// An event from no bus source (a login) is not a sighting on the bus.
	other := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/other", model.DeclaredModel{Provider: "anthropic"}))
		g.AddEvent(model.Event{IdentityID: "agent://acme.example/other", Type: model.EventLogin, Time: timeAt(1)})
	})
	got := subjectRow(t, Build(other, fakeMatch, nil), "agent://acme.example/other", "anthropic")
	if got.Gap != GapDeclaredNotSeen || len(got.Bus) != 0 {
		t.Errorf("a login with no bus source made %+v, want declared but not seen with no bus sighting", got)
	}
}

func TestAProviderInCodeThatNobodyWasSeenReachingIsNamedInCodeNotSeen(t *testing.T) {
	scan := &CodeScan{Root: "/src", Providers: map[string]CodeScanEntry{
		"openai":    {Sites: 2, Labels: []string{"OpenAI SDK (python)"}},
		"anthropic": {Sites: 1},
	}}
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/bot", model.DeclaredModel{Provider: "anthropic"}))
		g.AddEvent(egress("agent://acme.example/bot", "api.anthropic.com"))
	})
	r := Build(g, fakeMatch, scan)

	if got := rowFor(t, r, "openai"); !contains(got.Gaps, GapInCodeNotSeen) {
		t.Errorf("openai gaps = %v, want %q", got.Gaps, GapInCodeNotSeen)
	}
	if got := rowFor(t, r, "anthropic"); len(got.Gaps) != 0 {
		t.Errorf("anthropic gaps = %v, want none: it is declared, seen and in code", got.Gaps)
	}
	agrees := subjectRow(t, r, "agent://acme.example/bot", "anthropic")
	if agrees.Gap != GapAgrees || agrees.Code != CodeFound || agrees.CodeSites != 1 {
		t.Errorf("agreeing row = %+v, want agrees with the code found at 1 site", agrees)
	}

	var buf strings.Builder
	Human(&buf, r)
	if !strings.Contains(buf.String(), "whole estate") {
		t.Errorf("the human form never says the code column is for the whole estate:\n%s", buf.String())
	}

	// A provider the scan ran over and did not find is a different statement
	// from a scan that was never run.
	other := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/bot", model.DeclaredModel{Provider: "openai"}))
	})
	if row := subjectRow(t, Build(other, fakeMatch, &CodeScan{Root: "/src"}), "agent://acme.example/bot", "openai"); row.Code != CodeNotFound {
		t.Errorf("code = %q, want %q: the scan ran and found nothing", row.Code, CodeNotFound)
	}
}

func TestAnAbsentSourceIsARowAndNotAZero(t *testing.T) {
	empty := Build(graphWith(func(*graph.Store) {}), fakeMatch, nil)
	for _, source := range []string{SourceDeclared, SourceBus, SourceEgress, SourceEBPF, SourceCode} {
		row := sourceRow(t, empty, source)
		if row.State != "absent" || row.Count != 0 || strings.TrimSpace(row.Detail) == "" {
			t.Errorf("%s = %+v, want an absent row with a sentence saying what that means", source, row)
		}
	}
	if d := sourceRow(t, empty, SourceCode).Detail; !strings.Contains(d, "not a measurement") {
		t.Errorf("the code row never says its column is not a measurement: %q", d)
	}
	if d := sourceRow(t, empty, SourceEBPF).Detail; !strings.Contains(d, "Linux") {
		t.Errorf("the ebpf row never says the sensor is Linux-only: %q", d)
	}
	if len(empty.Subjects) != 0 {
		t.Errorf("an empty graph produced subject rows: %+v", empty.Subjects)
	}

	// Each source flips its own row, and only its own, when it is supplied.
	for name, tc := range map[string]struct {
		source string
		build  func(*graph.Store)
		scan   *CodeScan
	}{
		"declared": {SourceDeclared, func(g *graph.Store) {
			g.AddIdentity(passportAgent("agent://a/b", model.DeclaredModel{Provider: "openai"}))
		}, nil},
		"bus": {SourceBus, func(g *graph.Store) {
			g.AddEvent(model.Event{IdentityID: "agent://a/b", Type: model.EventSpendSpike, Source: "tokenfuse"})
		}, nil},
		"egress": {SourceEgress, func(g *graph.Store) { g.AddEvent(egress("agent://a/b", "example.com")) }, nil},
		"ebpf":   {SourceEBPF, func(g *graph.Store) { g.AddEvent(egress("proc:curl", "example.com")) }, nil},
		"code":   {SourceCode, func(*graph.Store) {}, &CodeScan{Root: "/src", Providers: map[string]CodeScanEntry{"openai": {Sites: 1}}}},
	} {
		got := Build(graphWith(tc.build), fakeMatch, tc.scan)
		if row := sourceRow(t, got, tc.source); row.State != "present" || row.Count == 0 {
			t.Errorf("%s supplied but its row is %+v", name, row)
		}
		for _, other := range []string{SourceDeclared, SourceBus, SourceEgress, SourceEBPF, SourceCode} {
			if other != tc.source && other != SourceEgress && other != SourceEBPF && sourceRow(t, got, other).State != "absent" {
				t.Errorf("%s supplied but %s reads present", name, other)
			}
		}
	}

	// An event from a source that is not on the bus (a login, say) is not a bus
	// sighting, and an egress flow is not one either.
	login := Build(graphWith(func(g *graph.Store) {
		g.AddEvent(model.Event{IdentityID: "agent://a/b", Type: model.EventLogin})
		g.AddEvent(egress("agent://a/b", "example.com"))
	}), fakeMatch, nil)
	if row := sourceRow(t, login, SourceBus); row.State != "absent" {
		t.Errorf("a login and an egress flow made the bus present: %+v", row)
	}

	// A scan that ran and found nothing is present, with a count of zero.
	if row := sourceRow(t, Build(graphWith(func(*graph.Store) {}), fakeMatch, &CodeScan{Root: "/src"}), SourceCode); row.State != "present" || row.Count != 0 || row.Detail == "" {
		t.Errorf("a scan that found nothing = %+v, want present, zero sites, and a sentence", row)
	}

	// A scan nobody ran is not a scan that found nothing.
	noScan := Build(graphWith(func(g *graph.Store) {
		g.AddEvent(egress("agent://a/b", "api.openai.com"))
	}), fakeMatch, nil)
	if row := subjectRow(t, noScan, "agent://a/b", "openai"); row.Code != CodeNotScanned {
		t.Errorf("code = %q, want %q: no scan was supplied", row.Code, CodeNotScanned)
	}
}

func TestAnAgentThatDeclaresNoModelIsNotAnAgentWithNoDeclaration(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/quiet"))
		g.AddIdentity(model.Identity{ID: "agent://acme.example/busonly", Type: model.IdentityAgent, Source: "tokenfuse"})
		g.AddEvent(model.Event{IdentityID: "agent://acme.example/busonly", Type: model.EventSpendSpike, Source: "tokenfuse"})
	})
	r := Build(g, fakeMatch, nil)

	if row := subjectRow(t, r, "agent://acme.example/quiet", ""); row.Gap != GapDeclaresNoModels {
		t.Errorf("gap = %q, want %q: a Passport that names no model is a declaration", row.Gap, GapDeclaresNoModels)
	}
	busonly := subjectRow(t, r, "agent://acme.example/busonly", "")
	if busonly.Gap != GapNoDeclaration {
		t.Errorf("gap = %q, want %q: nothing declares anything for this agent", busonly.Gap, GapNoDeclaration)
	}
	if len(busonly.Bus) != 1 || busonly.Bus[0].Source != "tokenfuse" {
		t.Errorf("bus = %+v, want the one tokenfuse sighting kept on the row", busonly.Bus)
	}
	for _, row := range r.Subjects {
		if row.Gap == GapDeclaredNotSeen {
			t.Errorf("%+v is called declared but not seen, and nothing was declared", row)
		}
	}
}

// ---- hostile input ----------------------------------------------------

const validQryxDoc = `{
  "schema": "qryx.ai-inventory/v1",
  "generatedAt": "2026-11-04T10:00:00Z",
  "root": "/src",
  "tool": { "name": "qryx", "version": "v1.1.1" },
  "entries": [
    { "provider": "openai", "role": "provider", "label": "OpenAI SDK (python)",
      "occurrences": [ { "file": "app.py", "line": 3 }, { "file": "b.py", "line": 9 } ] },
    { "provider": "", "role": "framework", "label": "LangChain (python)",
      "occurrences": [ { "file": "c.py", "line": 1 } ] }
  ],
  "limits": [ "An empty result is not proof that a tree uses no AI." ]
}`

func isDisplaySafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

func assertScanIsBounded(t *testing.T, what string, scan *CodeScan) {
	t.Helper()
	check := func(field, s string) {
		if !isDisplaySafe(s) {
			t.Errorf("%s: %s holds a control or invalid byte: %q", what, field, s)
		}
		if utf8.RuneCountInString(s) > 400 {
			t.Errorf("%s: %s is %d runes, past the bound", what, field, utf8.RuneCountInString(s))
		}
	}
	check("root", scan.Root)
	check("generatedAt", scan.GeneratedAt)
	check("tool", scan.Tool)
	if len(scan.Limits) > 80 {
		t.Errorf("%s: %d limits carried, past the bound", what, len(scan.Limits))
	}
	for _, l := range scan.Limits {
		check("limit", l)
	}
	if len(scan.Providers) > 512 {
		t.Errorf("%s: %d providers carried, past the bound", what, len(scan.Providers))
	}
	for p, e := range scan.Providers {
		check("provider", p)
		if len(e.Labels) > 32 {
			t.Errorf("%s: %d labels on %q, past the bound", what, len(e.Labels), p)
		}
		for _, l := range e.Labels {
			check("label", l)
		}
	}
}

func TestAHostileCodeScanIsRefusedOrReadWithinBounds(t *testing.T) {
	// Refused outright: the document is too large to read, is of the wrong
	// shape, or ends part way.
	oversize := `{"schema":"qryx.ai-inventory/v1","pad":"` + strings.Repeat("a", MaxCodeScanBytes) + `"}`
	refused := map[string]string{
		"oversize":                oversize,
		"entries is an object":    `{"schema":"qryx.ai-inventory/v1","entries":{"a":1}}`,
		"entries holds scalars":   `{"schema":"qryx.ai-inventory/v1","entries":[1,"x",[]]}`,
		"occurrences is a string": `{"schema":"qryx.ai-inventory/v1","entries":[{"provider":"openai","occurrences":"many"}]}`,
		"tool is a string":        `{"schema":"qryx.ai-inventory/v1","tool":"qryx"}`,
		"limits is an object":     `{"schema":"qryx.ai-inventory/v1","limits":{"a":"b"}}`,
		"trailing bytes":          validQryxDoc + `{"schema":"qryx.ai-inventory/v1"}`,
		"empty":                   ``,
		"null":                    `null`,
	}
	for name, doc := range refused {
		if _, err := ParseCodeScan([]byte(doc)); err == nil {
			t.Errorf("%s: a document of the wrong shape was accepted", name)
		}
	}

	// The file door refuses it before holding it, and a file that is not there
	// is an error of its own.
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(oversize), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodeScan(big); err == nil {
		t.Error("an oversize file was read")
	}
	if _, err := LoadCodeScan(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing file was read")
	}

	// Read, but only within bounds, and with nothing a terminal would act on.
	var entries, labels, limits []string
	for i := 0; i < 3000; i++ {
		labels = append(labels, fmt.Sprintf(`{"provider":"openai","label":"label %d","occurrences":[{"file":"f","line":1}]}`, i))
		limits = append(limits, fmt.Sprintf(`"limit %d"`, i))
	}
	for i := 0; i < 3000; i++ {
		entries = append(entries, fmt.Sprintf(`{"provider":"p%d","label":"l","occurrences":[{"file":"f","line":1}]}`, i))
	}
	accepted := map[string]string{
		"null entries and nulls inside": `{"schema":"qryx.ai-inventory/v1","entries":[null,{"provider":null,"label":null,"occurrences":null}],"limits":null}`,
		"control bytes everywhere": `{"schema":"qryx.ai-inventory/v1","root":"/src\u001b[2J\nroot","generatedAt":"\u0007","tool":{"name":"qryx\u001b]0;x\u0007","version":"\u202e1"},` +
			`"entries":[{"provider":"openai\u001b[31m","label":"lab\u001b[2Jel\r\nx","occurrences":[{"file":"f","line":1}]},{"provider":"openai","label":" \u0085"}],"limits":["a\u001b[2Jb\nc"]}`,
		"a provider that is not an id": `{"schema":"qryx.ai-inventory/v1","entries":[{"provider":"Open AI Inc.","occurrences":[{"file":"f","line":1}]},{"provider":"` + strings.Repeat("x", 5000) + `","occurrences":[{"file":"f","line":1}]}]}`,
		"thousands of labels":          `{"schema":"qryx.ai-inventory/v1","entries":[` + strings.Join(labels, ",") + `]}`,
		"thousands of providers":       `{"schema":"qryx.ai-inventory/v1","entries":[` + strings.Join(entries, ",") + `]}`,
		"thousands of limits":          `{"schema":"qryx.ai-inventory/v1","limits":[` + strings.Join(limits, ",") + `]}`,
		"very long strings":            `{"schema":"qryx.ai-inventory/v1","root":"` + strings.Repeat("r", 100000) + `","limits":["` + strings.Repeat("l", 100000) + `"]}`,
		"invalid utf-8":                "{\"schema\":\"qryx.ai-inventory/v1\",\"root\":\"/src\xff\xfe\"}",
	}
	for name, doc := range accepted {
		scan, err := ParseCodeScan([]byte(doc))
		if err != nil {
			t.Errorf("%s: refused, but this document is well formed and should be read within bounds: %v", name, err)
			continue
		}
		assertScanIsBounded(t, name, scan)
	}

	// A provider that is not an id names no provider, like an indirection, and
	// the limit says how many were set aside.
	scan, err := ParseCodeScan([]byte(accepted["a provider that is not an id"]))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Providers) != 0 {
		t.Errorf("a provider that is not an id was kept: %v", scan.SortedProviders())
	}
	if !strings.Contains(strings.Join(scan.Limits, " "), "not a provider id") {
		t.Errorf("the set-aside rows are not counted in the limits: %v", scan.Limits)
	}

	// Truncated at every offset: never a panic, and an error until the end.
	doc := []byte(validQryxDoc)
	for i := 0; i < len(doc); i++ {
		if _, err := ParseCodeScan(doc[:i]); err == nil {
			t.Fatalf("a document cut at byte %d of %d was accepted", i, len(doc))
		}
	}
	if _, err := ParseCodeScan(doc); err != nil {
		t.Fatalf("the intact document is refused: %v", err)
	}

	// A seeded sweep: 200 documents with bytes flipped, inserted and cut.
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		mutated := append([]byte(nil), doc...)
		for n := 1 + rng.Intn(6); n > 0; n-- {
			at := rng.Intn(len(mutated))
			switch rng.Intn(3) {
			case 0:
				mutated[at] = byte(rng.Intn(256))
			case 1:
				mutated = append(mutated[:at], append([]byte{byte(rng.Intn(32))}, mutated[at:]...)...)
			default:
				mutated = append(mutated[:at], mutated[at+1:]...)
			}
		}
		if scan, err := ParseCodeScan(mutated); err == nil {
			assertScanIsBounded(t, fmt.Sprintf("seed %d", seed), scan)
		}
	}
}

func TestHostileNamesNeverReachTheTerminalRaw(t *testing.T) {
	esc := "\x1b[2J\x1b]0;pwned\x07"
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://acme.example/"+esc+"bot\nforged line",
			model.DeclaredModel{Provider: "anthropic", Model: "m" + esc + strings.Repeat("z", 500)}))
		g.AddEvent(egress("agent://acme.example/"+esc+"bot\nforged line", "\u202e"+esc+"api.openai.com"))
		g.AddEvent(egress("proc:"+esc+"curl", "api.openai.com"))
	})
	scan := &CodeScan{Root: "/src" + esc, Tool: "qryx" + esc, GeneratedAt: esc,
		Limits:    []string{"limit" + esc + "\nnext"},
		Providers: map[string]CodeScanEntry{"openai": {Sites: 1, Labels: []string{"label" + esc}}}}
	r := Build(g, fakeMatch, scan)

	var human bytes.Buffer
	Human(&human, r)
	for n, line := range strings.Split(human.String(), "\n") {
		if !isDisplaySafe(line) && !strings.ContainsRune(line, '\t') {
			t.Errorf("line %d holds a raw control byte: %q", n, line)
		}
		if utf8.RuneCountInString(line) > 600 {
			t.Errorf("line %d is %d runes, so a hostile name stretched it", n, utf8.RuneCountInString(line))
		}
	}
	if !strings.Contains(human.String(), `\x1b`) {
		t.Errorf("the escape byte is not shown escaped, so it was dropped or never printed:\n%s", human.String())
	}
	if strings.Count(human.String(), "forged line") > 0 && strings.Contains(human.String(), "\nforged line") {
		t.Errorf("a line break in an id started a line of its own:\n%s", human.String())
	}

	var js bytes.Buffer
	if err := JSON(&js, r, "v-test", "2026-11-04T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(js.Bytes()) {
		t.Fatal("the JSON form of a hostile estate is not valid JSON")
	}
}

func TestTheReportStatesTheMonitoringLimitsAndRanksNothing(t *testing.T) {
	rich := graphWith(func(g *graph.Store) {
		g.AddIdentity(passportAgent("agent://a/declared", model.DeclaredModel{Provider: "anthropic"}))
		g.AddIdentity(passportAgent("agent://a/mixed", model.DeclaredModel{Provider: "anthropic"}))
		g.AddEvent(egress("agent://a/mixed", "api.openai.com"))
		g.AddEvent(egress("proc:curl", "api.openai.com"))
		g.AddIdentity(passportAgent("agent://a/quiet"))
		g.AddEvent(model.Event{IdentityID: "agent://a/declared", Type: model.EventSpendSpike, Source: "tokenfuse"})
	})
	for name, scan := range map[string]*CodeScan{"no scan": nil, "a scan": {Root: "/src", Providers: map[string]CodeScanEntry{"google": {Sites: 1}}}} {
		r := Build(rich, fakeMatch, scan)
		var human, js bytes.Buffer
		Human(&human, r)
		if err := JSON(&js, r, "v-test", "2026-11-04T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		for _, form := range []struct{ kind, text string }{{"human", human.String()}, {"json", js.String()}} {
			for _, want := range []string{"self-declared", "Linux", "open a socket"} {
				if !strings.Contains(form.text, want) {
					t.Errorf("%s / %s form never says %q", name, form.kind, want)
				}
			}
		}
		lower := strings.ToLower(human.String())
		for _, verdict := range []string{"critical", "high", "severity", "violation", "fix"} {
			if strings.Contains(lower, verdict) {
				t.Errorf("%s: the human form holds %q, which ranks or advises:\n%s", name, verdict, human.String())
			}
		}
	}
}

// shuffled hands identities back in a seeded random order, as a backend that
// promises no order may. The report must not depend on it.
type shuffled struct {
	graph.Reader
	seed int64
}

func (s shuffled) Identities() []*model.Identity {
	ids := s.Reader.Identities()
	rand.New(rand.NewSource(s.seed)).Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	return ids
}

func TestTheSameEstateInAnyOrderGivesTheSameReport(t *testing.T) {
	steps := []func(*graph.Store){
		func(g *graph.Store) {
			g.AddIdentity(passportAgent("agent://a/one", model.DeclaredModel{Provider: "anthropic", Model: "b"}, model.DeclaredModel{Provider: "openai", Model: "a"}))
		},
		func(g *graph.Store) {
			g.AddIdentity(passportAgent("agent://a/two", model.DeclaredModel{Provider: "google"}))
		},
		func(g *graph.Store) { g.AddEvent(egress("agent://a/one", "api.openai.com")) },
		func(g *graph.Store) { g.AddEvent(egress("proc:curl", "api.anthropic.com")) },
		func(g *graph.Store) { g.AddEvent(egress("agent://a/two", "api.openai.com")) },
		func(g *graph.Store) {
			g.AddEvent(model.Event{IdentityID: "agent://a/two", Type: model.EventSpendSpike, Source: "tokenfuse"})
		},
		func(g *graph.Store) {
			g.AddEvent(model.Event{IdentityID: "agent://a/one", Type: model.EventSpendSpike, Source: "wardryx"})
		},
	}
	render := func(order []int, shuffleSeed int64) string {
		g := graph.New(nil)
		for _, i := range order {
			steps[i](g)
		}
		var buf bytes.Buffer
		scan := &CodeScan{Root: "/src", Providers: map[string]CodeScanEntry{"openai": {Sites: 2}}}
		if err := JSON(&buf, Build(shuffled{g, shuffleSeed}, fakeMatch, scan), "v-test", "2026-11-04T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	forward := render([]int{0, 1, 2, 3, 4, 5, 6}, 0)
	for seed := int64(0); seed < 25; seed++ {
		order := rand.New(rand.NewSource(seed)).Perm(len(steps))
		// Identities must exist before their events can be attached to a
		// passport, so the declarations always go first, in any order.
		var decl, rest []int
		for _, i := range order {
			if i < 2 {
				decl = append(decl, i)
			} else {
				rest = append(rest, i)
			}
		}
		if got := render(append(decl, rest...), seed); got != forward {
			t.Fatalf("seed %d: the same estate loaded in another order gave a different report", seed)
		}
	}
	if !strings.Contains(forward, `"subjects"`) {
		t.Fatal("the JSON form carries no subjects")
	}
}

// FuzzParseCodeScan lets the Go fuzzer mutate qryx documents. Whatever it
// finds, a document is either refused or read within the bounds, and nothing
// panics. Run with: go test -fuzz FuzzParseCodeScan -fuzztime 60s ./internal/aiusage/
func FuzzParseCodeScan(f *testing.F) {
	f.Add([]byte(validQryxDoc))
	f.Add([]byte(`{"schema":"qryx.ai-inventory/v1","entries":[null,{"provider":"openai\u001b[2J","occurrences":[{}]}],"limits":["‮"]}`))
	f.Add([]byte(`{"schema":"qryx.ai-inventory/v1","entries":{"a":1}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		scan, err := ParseCodeScan(data)
		if err == nil {
			assertScanIsBounded(t, "fuzz", scan)
		}
	})
}
