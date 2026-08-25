package aiusage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// fakeMatch is the observed-side vocabulary this package is told about, rather
// than the one the detectors carry. Stating it here is the point of taking the
// matcher as a parameter: a test says exactly which hosts it means and does not
// inherit a table that will grow.
func fakeMatch(host string) (string, bool) {
	switch {
	case strings.HasSuffix(host, "api.anthropic.com"):
		return "anthropic", true
	case strings.HasSuffix(host, "api.openai.com"):
		return "openai", true
	case strings.HasSuffix(host, "generativelanguage.googleapis.com"):
		return "google", true
	}
	return "", false
}

func egress(id, host string) model.Event {
	return model.Event{IdentityID: id, Type: model.EventEgress, Resource: host}
}

func graphWith(fn func(*graph.Store)) *graph.Store {
	g := graph.New(nil)
	fn(g)
	return g
}

func rowFor(t *testing.T, r Report, provider string) Row {
	t.Helper()
	for _, row := range r.Rows {
		if row.Provider == provider {
			return row
		}
	}
	t.Fatalf("no row for %q; rows: %+v", provider, r.Rows)
	return Row{}
}

// TestSpellingIsNotDrift is the defect that blocked this whole report, and it
// is the reason SPEC 4.7 exists.
//
// A Passport is written by a person, so it carries whatever they typed:
// "Anthropic" as readily as "anthropic". 4.7 obliges a consumer to lowercase
// both sides before comparing and to do nothing else. Without that, an agent
// that declares Anthropic and reaches Anthropic produces two rows that look
// like a declaration nobody honoured and traffic nobody declared, and a reader
// cannot tell that from real drift.
func TestSpellingIsNotDrift(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{
			ID: "agent:a", Type: model.IdentityAgent,
			DeclaredModels: []model.DeclaredModel{{Provider: "Anthropic"}},
		})
		g.AddEvent(egress("agent:a", "api.anthropic.com"))
	})

	got := Build(g, fakeMatch, nil)
	if len(got.Rows) != 1 {
		t.Fatalf("got %d rows, want 1; a spelling difference split one provider in two: %+v", len(got.Rows), got.Rows)
	}
	row := got.Rows[0]
	if row.Provider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", row.Provider)
	}
	if !row.Declared() || !row.Observed() {
		t.Errorf("declared=%v observed=%v, want both: the agent declared it and reached it", row.Declared(), row.Observed())
	}
}

// TestTheThreeSidesAreReportedSeparately holds the shape of the answer: each
// side is its own column, and a provider known to only one of them still gets
// a row. A report that only listed agreement would hide every case worth
// looking at.
func TestTheThreeSidesAreReportedSeparately(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{
			ID: "agent:declares-only", Type: model.IdentityAgent,
			DeclaredModels: []model.DeclaredModel{{Provider: "google"}},
		})
		g.AddIdentity(model.Identity{ID: "agent:reaches-only", Type: model.IdentityAgent})
		g.AddEvent(egress("agent:reaches-only", "api.openai.com"))
	})
	scan := &CodeScan{Providers: map[string]CodeScanEntry{
		"mistral": {Sites: 2, Labels: []string{"Mistral AI SDK (python)"}},
	}}

	got := Build(g, fakeMatch, scan)

	google := rowFor(t, got, "google")
	if !google.Declared() || google.Observed() || google.Coded() {
		t.Errorf("google: declared=%v observed=%v coded=%v, want declared only", google.Declared(), google.Observed(), google.Coded())
	}
	openai := rowFor(t, got, "openai")
	if openai.Declared() || !openai.Observed() || openai.Coded() {
		t.Errorf("openai: declared=%v observed=%v coded=%v, want observed only", openai.Declared(), openai.Observed(), openai.Coded())
	}
	mistral := rowFor(t, got, "mistral")
	if mistral.Declared() || mistral.Observed() || !mistral.Coded() {
		t.Errorf("mistral: declared=%v observed=%v coded=%v, want coded only", mistral.Declared(), mistral.Observed(), mistral.Coded())
	}
	if mistral.CodeSites != 2 {
		t.Errorf("mistral code sites = %d, want 2", mistral.CodeSites)
	}
}

// TestOneAgentCountedOnce pins the de-duplication both sides need. An agent
// that reaches one provider on twenty events is one agent, and a Passport that
// names a provider twice, once bare and once with an endpoint, is one
// declaration. Counting events instead of agents would make the column measure
// how chatty an agent is.
func TestOneAgentCountedOnce(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{
			ID: "agent:busy", Type: model.IdentityAgent,
			DeclaredModels: []model.DeclaredModel{
				{Provider: "anthropic"},
				{Provider: "anthropic", Endpoint: "api.anthropic.com"},
			},
		})
		for i := 0; i < 5; i++ {
			g.AddEvent(egress("agent:busy", "api.anthropic.com"))
		}
	})

	row := rowFor(t, Build(g, fakeMatch, nil), "anthropic")
	if len(row.DeclaredBy) != 1 {
		t.Errorf("declared by %v, want one agent named once", row.DeclaredBy)
	}
	if len(row.ObservedBy) != 1 {
		t.Errorf("observed by %v, want one agent named once", row.ObservedBy)
	}
}

// TestReportAlwaysStatesItsLimits is the half a consumer can act on. An empty
// report looks exactly like an estate that uses no AI, and only the limits say
// otherwise.
func TestReportAlwaysStatesItsLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan *CodeScan
	}{
		{"no code scan at all", nil},
		{"with a code scan", &CodeScan{Limits: []string{"the scan's own limit"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(graphWith(func(*graph.Store) {}), fakeMatch, tc.scan)
			if len(got.Limits) == 0 {
				t.Fatal("no limits, so an empty report reads as proof that nothing here uses AI")
			}
			joined := strings.Join(got.Limits, " ")
			if !strings.Contains(joined, "is not a provider nobody uses") {
				t.Errorf("limits never say an absent provider is not an unused one: %q", joined)
			}
			if tc.scan != nil && !strings.Contains(joined, "the scan's own limit") {
				t.Error("the scan's own limits were dropped, so the report claims to see more than the scan did")
			}
		})
	}
}

// TestCodeScanAbsenceIsVisible: a report built with no source scan must not
// present its empty third column as a measurement. Coded=false then means
// "nobody looked", and CodeScan.Present is the only thing that says which.
func TestCodeScanAbsenceIsVisible(t *testing.T) {
	got := Build(graphWith(func(*graph.Store) {}), fakeMatch, nil)
	if got.CodeScan.Present {
		t.Error("a report built with no scan says it has one")
	}
	withScan := Build(graphWith(func(*graph.Store) {}), fakeMatch, &CodeScan{Root: "/src"})
	if !withScan.CodeScan.Present || withScan.CodeScan.Root != "/src" {
		t.Errorf("a report built with a scan does not name it: %+v", withScan.CodeScan)
	}
}

// TestRowsAreSorted pins determinism. The rows are assembled through a map, so
// unsorted output would differ between two runs of one unchanged estate and
// every diff downstream would be noise.
func TestRowsAreSorted(t *testing.T) {
	g := graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{
			ID: "agent:a", Type: model.IdentityAgent,
			DeclaredModels: []model.DeclaredModel{
				{Provider: "openai"}, {Provider: "anthropic"}, {Provider: "google"},
			},
		})
	})
	for i := 0; i < 8; i++ {
		got := Build(g, fakeMatch, nil)
		var order []string
		for _, r := range got.Rows {
			order = append(order, r.Provider)
		}
		if len(order) != 3 || order[0] != "anthropic" || order[1] != "google" || order[2] != "openai" {
			t.Fatalf("run %d: order = %v, want anthropic google openai", i, order)
		}
	}
}

// TestAgreesNeedsAllThree is small and worth pinning, because the tempting
// reading of two-out-of-three is "close enough" and it is not: a provider in
// the code and on the wire but in no declaration is exactly the case an
// inventory exists to surface.
func TestAgreesNeedsAllThree(t *testing.T) {
	all := Row{Provider: "x", DeclaredBy: []string{"a"}, ObservedBy: []string{"a"}, CodeSites: 1}
	if !all.Agrees() {
		t.Error("a provider all three sides know does not agree")
	}
	noDeclaration := Row{Provider: "x", ObservedBy: []string{"a"}, CodeSites: 1}
	if noDeclaration.Agrees() {
		t.Error("a provider in the code and on the wire but declared nowhere reads as agreement")
	}
}

// TestHumanSaysWhenThereIsNoCodeScan is the one line in the human output that
// must never be dropped. Without a scan the last column is all zeros, and a
// zero that means "nobody looked" is indistinguishable from a zero that means
// "looked and found nothing" unless the report says which.
func TestHumanSaysWhenThereIsNoCodeScan(t *testing.T) {
	var buf strings.Builder
	Human(&buf, Build(graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{
			ID: "agent:a", Type: model.IdentityAgent,
			DeclaredModels: []model.DeclaredModel{{Provider: "anthropic"}},
		})
	}), fakeMatch, nil))

	out := buf.String()
	if !strings.Contains(out, "not a measurement") {
		t.Errorf("a report with no code scan does not say its CODE column is not a measurement:\n%s", out)
	}
	if !strings.Contains(out, "qryx scan --format ai-inventory") {
		t.Error("it does not say how to get one")
	}
}

// TestHumanNamesTheDisagreementRatherThanRankingIt holds the boundary this
// package is built around. It reports; internal/detect judges. A column
// reading "high" or "fix this" here would be a detector wearing a report's
// clothes, and it would be a detector with no subject, since the coded side
// has no identity to attach a finding to.
func TestHumanNamesTheDisagreementRatherThanRankingIt(t *testing.T) {
	var buf strings.Builder
	Human(&buf, Build(graphWith(func(g *graph.Store) {
		g.AddIdentity(model.Identity{ID: "agent:a", Type: model.IdentityAgent})
		g.AddEvent(egress("agent:a", "api.openai.com"))
	}), fakeMatch, nil))

	out := buf.String()
	if !strings.Contains(out, "reached, and declared by nobody") {
		t.Errorf("the disagreement is not named:\n%s", out)
	}
	for _, verdict := range []string{"critical", "high", "severity", "violation", "fix"} {
		if strings.Contains(strings.ToLower(out), verdict) {
			t.Errorf("the report scores its rows (%q), which is internal/detect's job:\n%s", verdict, out)
		}
	}
}

// TestJSONCarriesTheLimitsAndTheScanRef: the machine form must carry both, or
// a consumer that only reads JSON loses exactly the two things that stop this
// being read as proof of absence.
func TestJSONCarriesTheLimitsAndTheScanRef(t *testing.T) {
	var buf strings.Builder
	r := Build(graphWith(func(*graph.Store) {}), fakeMatch, &CodeScan{Root: "/src"})
	if err := JSON(&buf, r, "v0-test", "2026-08-25T00:00:00Z"); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if doc["schema"] != Schema {
		t.Errorf("schema = %v, want %s", doc["schema"], Schema)
	}
	if limits, _ := doc["limits"].([]any); len(limits) == 0 {
		t.Error("the JSON form carries no limits")
	}
	ref, _ := doc["code_scan"].(map[string]any)
	if ref["present"] != true || ref["root"] != "/src" {
		t.Errorf("code_scan = %v, want the scan it was built with", ref)
	}
}
