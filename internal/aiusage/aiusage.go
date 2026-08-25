// Package aiusage answers one question about an operator's own estate: where
// does it use AI models, and do the three places that know disagree?
//
// agent-passport SPEC 4.5 has always described this comparison. A Passport
// DECLARES the providers an agent is meant to use; a source scan finds what the
// CODE can reach; an egress sensor sees what it OBSERVABLY reached. 4.5 says a
// disagreement between the three "is the finding such an inventory exists to
// surface", and until SPEC 4.7 registered the spelling the three sides could
// not be compared at all: the same provider was `google` in one, `Google
// Gemini` in another, and whatever an author typed in the third.
//
// # WHY THIS IS A REPORT AND NOT A DETECTOR
//
// The coded side has no subject. A source scan finds a file and a line; a
// repository is not an agent, and no Passport field binds one to the other. So
// the third leg cannot produce an alert about an identity even in principle,
// and a reconciliation built on it is an estate-level inventory rather than a
// per-identity judgement. That is also the question the AI Act's
// code-inventory obligation actually asks, which is about an organisation
// rather than about one process.
//
// The per-identity half already exists and stays where it is:
// detectors.UndeclaredLLM compares one agent's declaration against that same
// agent's observed egress, which it can do because both sides carry the
// identity.
//
// # WHY IT TAKES ITS HOST MATCHER RATHER THAN IMPORTING ONE
//
// The observed vocabulary lives with the detectors, and reaching into that
// package from here would tie a report to a detector's internals for the sake
// of one map. A function parameter keeps the dependency pointing one way and
// lets these tests state exactly which hosts they mean, instead of inheriting a
// table that will grow.
package aiusage

import (
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// MatchHost reports the registered provider id a destination host belongs to.
// The second return is false when the host is not a model API this sensor
// knows, which is not the same as "not a model API".
type MatchHost func(host string) (string, bool)

// Row is one provider, with what each of the three sides says about it.
//
// The counts are of AGENTS on the declared and observed sides and of source
// SITES on the coded side, because those are the units each side actually has.
// Presenting them as one number would invite a reader to compare them, and
// "three agents" against "five call sites" is not a comparison.
type Row struct {
	Provider string `json:"provider"`

	// DeclaredBy is every agent whose Passport names this provider, sorted.
	DeclaredBy []string `json:"declared_by"`
	// ObservedBy is every identity seen reaching it, sorted.
	ObservedBy []string `json:"observed_by"`
	// CodeSites is how many places the source scan found it. Zero means the
	// scan did not find it, never that the code cannot reach it: see Limits.
	CodeSites int `json:"code_sites"`
	// CodeLabels are the human labels the scan attached, e.g. "OpenAI SDK
	// (python)", sorted and de-duplicated.
	CodeLabels []string `json:"code_labels,omitempty"`
}

// Declared, Observed and Coded say which sides know about this provider at
// all. A reader wants the SHAPE of the disagreement before the counts, and a
// row where all three are true is the boring one.
func (r Row) Declared() bool { return len(r.DeclaredBy) > 0 }
func (r Row) Observed() bool { return len(r.ObservedBy) > 0 }
func (r Row) Coded() bool    { return r.CodeSites > 0 }

// Agrees reports whether all three sides say the same thing about this
// provider. It is deliberately not called "ok": a provider in the code and
// nowhere else is often correct (a disabled branch, a vendored example), and a
// provider observed but never declared is often not. This function ranks
// nothing.
func (r Row) Agrees() bool { return r.Declared() && r.Observed() && r.Coded() }

// Report is the whole answer, plus what it could not see.
type Report struct {
	Rows []Row `json:"rows"`

	// CodeScan describes the source scan this was built with, or is empty when
	// none was supplied. A report with no code leg is still useful and must
	// say so rather than let a reader take an absent third column for a zero.
	CodeScan CodeScanRef `json:"code_scan"`

	// Limits carries what none of the three sides can see, including the
	// scan's own declared limits. It is never empty, because an inventory that
	// finds nothing looks exactly like an estate that uses no AI.
	Limits []string `json:"limits"`
}

// CodeScanRef identifies the scan whose findings are in the coded column.
type CodeScanRef struct {
	Present     bool   `json:"present"`
	Root        string `json:"root,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
	Tool        string `json:"tool,omitempty"`
}

// baseLimits is what is true of every report this package writes, whatever
// went into it. The scan's own limits are appended to these.
var baseLimits = []string{
	"A provider in no column is not a provider nobody uses: it is one nothing here can see.",
	"The observed column shows only hosts this sensor recognises, and only traffic it captured.",
	"The declared column is a self-declaration. agent-passport SPEC 4.5 says so, and nothing here attests it.",
	"The coded column has no agent: a source scan finds a file and a line, and no field binds a repository to an identity. Its counts are estate-wide.",
}

// Build reconciles the three sides.
//
// declared and observed come from the graph; coded comes from a source scan
// loaded separately, which may be absent. Providers are compared on the
// registered id from SPEC 4.7, lowercased on both sides and not reshaped
// further, which is what 4.7 obliges a consumer to do and the most a consumer
// may do: anything cleverer turns a spelling into an assertion about which
// model an agent uses.
func Build(g graph.Reader, match MatchHost, scan *CodeScan) Report {
	rows := map[string]*Row{}
	row := func(provider string) *Row {
		p := normalize(provider)
		if p == "" {
			return nil
		}
		if rows[p] == nil {
			rows[p] = &Row{Provider: p}
		}
		return rows[p]
	}

	seenDeclared := map[string]map[string]bool{}
	seenObserved := map[string]map[string]bool{}
	add := func(seen map[string]map[string]bool, provider, id string) bool {
		if seen[provider] == nil {
			seen[provider] = map[string]bool{}
		}
		if seen[provider][id] {
			return false
		}
		seen[provider][id] = true
		return true
	}

	for _, identity := range g.Identities() {
		for _, m := range identity.DeclaredModels {
			r := row(m.Provider)
			if r != nil && add(seenDeclared, r.Provider, identity.ID) {
				r.DeclaredBy = append(r.DeclaredBy, identity.ID)
			}
		}
		for _, e := range identity.Events {
			if e.Type != model.EventEgress {
				continue
			}
			provider, ok := match(e.Resource)
			if !ok {
				continue
			}
			r := row(provider)
			if r != nil && add(seenObserved, r.Provider, identity.ID) {
				r.ObservedBy = append(r.ObservedBy, identity.ID)
			}
		}
	}

	report := Report{Limits: append([]string{}, baseLimits...)}
	if scan != nil {
		report.CodeScan = CodeScanRef{
			Present:     true,
			Root:        scan.Root,
			GeneratedAt: scan.GeneratedAt,
			Tool:        scan.Tool,
		}
		report.Limits = append(report.Limits, scan.Limits...)
		for provider, entry := range scan.Providers {
			r := row(provider)
			if r == nil {
				continue
			}
			r.CodeSites += entry.Sites
			r.CodeLabels = append(r.CodeLabels, entry.Labels...)
		}
	}

	for _, r := range rows {
		sort.Strings(r.DeclaredBy)
		sort.Strings(r.ObservedBy)
		r.CodeLabels = dedupeSorted(r.CodeLabels)
		report.Rows = append(report.Rows, *r)
	}
	// Sorted, because the map above randomises and a report that reorders
	// between two runs of one unchanged estate makes every diff noise.
	sort.Slice(report.Rows, func(i, j int) bool {
		return report.Rows[i].Provider < report.Rows[j].Provider
	})
	return report
}

// normalize is the whole of what SPEC 4.7 permits a consumer to do to a
// provider before comparing it: lowercase it, and trim the surrounding
// whitespace a hand-edited Passport carries. Nothing else. Stripping
// punctuation or folding an unregistered value onto a registered one would
// turn a spelling into a claim about which model an agent uses.
func normalize(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
