package aiusage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// The names of the disagreements. They are constants so a report, its JSON and
// the README table cannot spell one differently, and so scripts/usage-gaps-complete.sh
// has one list to compare the README against.
const (
	GapAgrees            = "agrees"
	GapDeclaredNotSeen   = "declared_not_seen"
	GapDeclaredBusOnly   = "declared_bus_only"
	GapSeenNotDeclared   = "seen_not_declared"
	GapSeenNoDeclaration = "seen_no_declaration"
	GapDeclaresNoModels  = "declares_no_models"
	GapNoDeclaration     = "no_declaration"
	GapInCodeNotSeen     = "in_code_not_seen"
)

// What the egress side saw of one subject and provider.
const (
	SeenEgress  = "egress"
	SeenBusOnly = "bus_only"
	SeenNone    = "none"
)

// What the code scan says about a provider, which is never about a subject.
const (
	CodeFound      = "found"
	CodeNotFound   = "not_found"
	CodeNotScanned = "not_scanned"
)

// The sources a report is built from, each of which may be absent.
const (
	SourceDeclared = "declared"
	SourceBus      = "bus"
	SourceEgress   = "egress"
	SourceEBPF     = "ebpf"
	SourceCode     = "code"
)

// SourceRow says whether one source contributed to the report and what it
// held. An absent source is a row, never a missing column and never a zero.
type SourceRow struct {
	Source string `json:"source"`
	State  string `json:"state"` // "present" or "absent"
	Count  int    `json:"count"`
	Detail string `json:"detail"`
}

// BusCount is how many events one bus source wrote about a subject.
type BusCount struct {
	Source string `json:"source"`
	Events int    `json:"events"`
}

// SubjectRow is one subject (an agent, a service, a process) and one provider.
type SubjectRow struct {
	Subject     string     `json:"subject"`
	Kind        string     `json:"kind"`
	Attribution string     `json:"attribution,omitempty"`
	Provider    string     `json:"provider,omitempty"`
	Declared    bool       `json:"declared"`
	Models      []string   `json:"models,omitempty"`
	Seen        string     `json:"seen"`
	Via         []string   `json:"via,omitempty"`
	Hosts       []string   `json:"hosts,omitempty"`
	Bus         []BusCount `json:"bus,omitempty"`
	Code        string     `json:"code,omitempty"`
	CodeSites   int        `json:"code_sites,omitempty"`
	Gap         string     `json:"gap"`
}

// gapText is the sentence for each named disagreement. It says what is
// missing and never what to do about it: the right action differs per estate,
// and this report ranks nothing (AGENTS.md invariant 10).
var gapText = map[string]string{
	GapAgrees:            "",
	GapDeclaredNotSeen:   "declared, and not seen reaching it",
	GapDeclaredBusOnly:   "declared; active on the bus, which names no provider, and not seen reaching it directly",
	GapSeenNotDeclared:   "seen reaching it, and not declared (this subject declares other providers)",
	GapSeenNoDeclaration: "seen reaching it; this subject declares nothing to compare with",
	GapDeclaresNoModels:  "declares no model; nothing seen",
	GapNoDeclaration:     "no declaration loaded for this subject; nothing seen",
	GapInCodeNotSeen:     "in code, not seen in operation",
}

// GapText returns the sentence for a gap code, or the code itself for one this
// version does not know, so a newer document never renders blank.
func GapText(gap string) string {
	if s, ok := gapText[gap]; ok {
		return s
	}
	return escape(gap, maxShown)
}

// subjectFacts is what one identity says on each side.
type subjectFacts struct {
	id       *model.Identity
	declared map[string][]string // provider -> declared model names
	hosts    map[string]bool     // endpoint hosts the declaration names
	seen     map[string]map[string]bool
	bus      map[string]int
}

func hostOnly(dest string) string {
	host := dest
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func isCaptured(id string) bool {
	return strings.HasPrefix(id, ebpfcapture.IdentityPrefix) || strings.HasPrefix(id, ebpfcapture.ClaimedPrefix)
}

// hasDeclaration reports whether a declaration was loaded for the identity at
// all. A Passport that names no model is still a declaration; an agent known
// only from the bus has none. The two get different names.
func hasDeclaration(id *model.Identity) bool {
	return id.Source == "passport" || len(id.DeclaredModels) > 0 || id.Attestation != ""
}

func classify(id *model.Identity) (kind, attribution string) {
	switch {
	case strings.HasPrefix(id.ID, ebpfcapture.ClaimedPrefix):
		return "claimed agent", "self-declared"
	case strings.HasPrefix(id.ID, ebpfcapture.IdentityPrefix):
		return "process", "process name"
	}
	switch id.Type {
	case model.IdentityAgent:
		return "agent", ""
	case model.IdentityServiceAccount:
		return "service account", ""
	case model.IdentityKey:
		return "key", ""
	case model.IdentityMCPServer:
		return "mcp server", ""
	case model.IdentityHuman:
		return "human", ""
	}
	return string(id.Type), ""
}

func gather(id *model.Identity, match MatchHost) subjectFacts {
	f := subjectFacts{
		id:       id,
		declared: map[string][]string{},
		hosts:    map[string]bool{},
		seen:     map[string]map[string]bool{},
		bus:      map[string]int{},
	}
	for _, m := range id.DeclaredModels {
		p := normalize(m.Provider)
		if p == "" {
			continue
		}
		if name := strings.TrimSpace(m.Model); name != "" {
			f.declared[p] = append(f.declared[p], name)
		} else if _, ok := f.declared[p]; !ok {
			f.declared[p] = nil
		}
		if m.Endpoint != "" {
			f.hosts[hostOnly(m.Endpoint)] = true
		}
	}
	for _, e := range id.Events {
		if e.Type == model.EventEgress {
			provider, ok := match(e.Resource)
			p := normalize(provider)
			if !ok || p == "" {
				continue
			}
			if f.seen[p] == nil {
				f.seen[p] = map[string]bool{}
			}
			f.seen[p][hostOnly(e.Resource)] = true
		} else if e.Source != "" {
			f.bus[e.Source]++
		}
	}
	return f
}

// coveredByEndpoint reports whether every host a provider was reached on is an
// endpoint the declaration names. undeclared_llm exempts a host the same way,
// so the report and the detector cannot disagree about it.
func (f subjectFacts) coveredByEndpoint(provider string) bool {
	hosts := f.seen[provider]
	if len(hosts) == 0 {
		return false
	}
	for h := range hosts {
		if !f.hosts[h] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func busCounts(bus map[string]int) []BusCount {
	var out []BusCount
	for source, n := range bus {
		out = append(out, BusCount{Source: source, Events: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// buildSubjects joins the sides per subject and provider and states which
// sources the join was built from. Subjects are the agents, and any other
// identity that declared or reached a provider; an identity with no AI fact
// that is not an agent is not a subject.
func buildSubjects(g graph.Reader, match MatchHost, scan *CodeScan) ([]SubjectRow, []SourceRow) {
	var rows []SubjectRow
	var (
		declaredSubjects, modelSubjects int
		busEvents, egressEvents         int
		ebpfEvents, providerFlows       int
		busSubjects, egressSubjects     = map[string]bool{}, map[string]bool{}
		ebpfSubjects                    = map[string]bool{}
		busSources                      = map[string]bool{}
	)

	for _, id := range g.Identities() {
		f := gather(id, match)
		if hasDeclaration(id) {
			declaredSubjects++
			if len(f.declared) > 0 {
				modelSubjects++
			}
		}
		for _, e := range id.Events {
			switch {
			case e.Type == model.EventEgress:
				egressEvents++
				egressSubjects[id.ID] = true
				if isCaptured(id.ID) {
					ebpfEvents++
					ebpfSubjects[id.ID] = true
				}
				if _, ok := match(e.Resource); ok {
					providerFlows++
				}
			case e.Source != "":
				busEvents++
				busSubjects[id.ID] = true
				busSources[e.Source] = true
			}
		}

		if !id.IsAgent() && len(f.declared) == 0 && len(f.seen) == 0 {
			continue
		}
		kind, attribution := classify(id)
		via := "egress-log"
		if isCaptured(id.ID) {
			via = "ebpf"
		}

		providers := map[string]bool{}
		for p := range f.declared {
			providers[p] = true
		}
		for p := range f.seen {
			providers[p] = true
		}

		if len(providers) == 0 {
			gap := GapNoDeclaration
			if hasDeclaration(id) {
				gap = GapDeclaresNoModels
			}
			seen := SeenNone
			if len(f.bus) > 0 {
				seen = SeenBusOnly
			}
			rows = append(rows, SubjectRow{
				Subject: id.ID, Kind: kind, Attribution: attribution,
				Seen: seen, Bus: busCounts(f.bus), Gap: gap,
			})
			continue
		}

		for _, p := range sortedKeys(providers) {
			_, declaredHere := f.declared[p]
			declared := declaredHere || f.coveredByEndpoint(p)
			row := SubjectRow{
				Subject: id.ID, Kind: kind, Attribution: attribution, Provider: p,
				Declared: declared, Seen: SeenNone, Bus: busCounts(f.bus),
			}
			row.Models = dedupeSorted(f.declared[p])
			if hosts, reached := f.seen[p]; reached {
				row.Seen = SeenEgress
				row.Hosts = sortedKeys(hosts)
				row.Via = []string{via}
			} else if len(f.bus) > 0 {
				row.Seen = SeenBusOnly
			}
			switch {
			case declared && row.Seen == SeenEgress:
				row.Gap = GapAgrees
			case declared && row.Seen == SeenBusOnly:
				row.Gap = GapDeclaredBusOnly
			case declared:
				row.Gap = GapDeclaredNotSeen
			case len(f.declared) > 0:
				row.Gap = GapSeenNotDeclared
			default:
				row.Gap = GapSeenNoDeclaration
			}
			switch {
			case scan == nil:
				row.Code = CodeNotScanned
			case scan.Providers[p].Sites > 0:
				row.Code, row.CodeSites = CodeFound, scan.Providers[p].Sites
			default:
				row.Code = CodeNotFound
			}
			rows = append(rows, row)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Subject != rows[j].Subject {
			return rows[i].Subject < rows[j].Subject
		}
		return rows[i].Provider < rows[j].Provider
	})

	sources := []SourceRow{
		makeSourceRow(SourceDeclared, declaredSubjects,
			fmt.Sprintf("%d subject(s) carry a declaration, %d of them name at least one model", declaredSubjects, modelSubjects),
			"no Passport or other declaration was loaded, so the DECLARED column is not a measurement; a subject with no declaration here is not one that declares nothing"),
		makeSourceRow(SourceBus, busEvents,
			fmt.Sprintf("%d event(s) from %s about %d subject(s); the bus names no provider, so it shows a subject is active through an enforcement point and not which provider it calls",
				busEvents, listNames(busSources), len(busSubjects)),
			"no agent-event bus file was loaded, so no subject can be said to be active on the bus"),
		makeSourceRow(SourceEgress, egressEvents,
			fmt.Sprintf("%d flow(s) about %d subject(s), %d of them to a model provider the host vocabulary recognises",
				egressEvents, len(egressSubjects), providerFlows),
			"no egress log or capture was loaded, so no subject can be said to have reached a provider"),
		makeSourceRow(SourceEBPF, ebpfEvents,
			fmt.Sprintf("%d flow(s) from %d captured process(es); a flow is attributed by the process's own name or its own claim",
				ebpfEvents, len(ebpfSubjects)),
			"no eBPF capture is in this graph; the sensor is Linux-only and needs privilege, so a laptop is not covered, and nothing here says whether a capture ran and saw nothing"),
	}
	if scan != nil {
		sites := 0
		for _, e := range scan.Providers {
			sites += e.Sites
		}
		sources = append(sources, SourceRow{
			Source: SourceCode, State: "present", Count: sites,
			Detail: strings.TrimSpace(fmt.Sprintf("%s scanned %s: %d site(s) across %d provider(s); a scan has no subject, so its counts are for the whole estate",
				strings.TrimSpace(scan.Tool), scan.Root, sites, len(scan.Providers))),
		})
	} else {
		sources = append(sources, makeSourceRow(SourceCode, 0, "",
			"no code scan was supplied (run `qryx scan --format ai-inventory <path>` and pass it with --code-scan); the CODE column is not a measurement, and a scan nobody ran is not a tree with nothing in it"))
	}
	return rows, sources
}

// makeSourceRow is present when it counted anything and absent otherwise, and in
// either case carries the sentence that says what that means.
func makeSourceRow(source string, count int, present, absent string) SourceRow {
	if count > 0 {
		return SourceRow{Source: source, State: "present", Count: count, Detail: present}
	}
	return SourceRow{Source: source, State: "absent", Detail: absent}
}

func listNames(set map[string]bool) string {
	names := sortedKeys(set)
	for i, n := range names {
		names[i] = escape(n, 40)
	}
	return strings.Join(names, ", ")
}
