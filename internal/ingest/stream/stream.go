// Package stream decides which `source` values a stream file may carry.
//
// The shared event bus is one directory with one NDJSON file per writer, and
// every reader trusted the `source` field inside each line: a line claiming
// `source: wardryx` inside tokenfuse.ndjson was rendered, counted and mailed
// as wardryx. The directory is writable by every plane (agent-event chains are
// unkeyed, so a forged line can carry a valid chain), which makes that field
// the one place where a co-tenant could speak in another plane's name.
//
// The rule, held by the reader because the reader is the one party that sees
// both the file and the claim: an event is processed as its claimed source
// only when the file it was read from may carry that source.
//
// # Where the allowed set comes from
//
//   - By convention a stream named <source>.ndjson carries <source>. That is
//     the layout every writer follows and genaryx's `bus.rs` documents.
//   - A small, explicit table of the files that legitimately differ, measured
//     against the producers and the three launchers (see [exceptions]).
//   - Whatever the operator adds through the environment (see [ParseExtra]),
//     for a box whose layout the table does not know.
//
// A file whose stem is none of those is an UNKNOWN stream. It is not silently
// trusted and it is not silently dropped either: a line whose source equals
// the stem is still read, because a new plane must not go deaf the day it is
// deployed, and the caller is told once that the box does not know the stream.
// A line in an unknown stream that claims any OTHER source is refused, which
// is the forgery case.
//
// This package does no I/O: it is a pure table and a pure decision.
//
// It is a copy. heraldyx carries the same table in its own `internal/stream`
// (agent-stack-go is the shared module, and moving the table there is a
// release of that module, which this change does not make), and nothing holds
// the two equal; see AGENTS.md invariant 17.
package stream

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Verdict is what [Policy.Check] decides about one line.
type Verdict int

const (
	// Allowed: the stream's declared set contains the claimed source.
	Allowed Verdict = iota
	// AllowedUnknownStem: the stream is not declared anywhere and the line
	// claims the stream's own stem. Processed, and counted by the caller.
	AllowedUnknownStem
	// Foreign: the claimed source is not allowed for this stream. Not
	// processed as that source.
	Foreign
)

// knownSources are the sources agent-passport SPEC.md 6.2 registers, as read
// by estate-gates C4's producer table. Each is a single-source stream under
// the stem == source convention. A source the registry gains later is an
// unknown stream here until this list or the operator's declaration learns it,
// which is the loud direction to be wrong in.
var knownSources = []string{
	"console", "costcrew", "engram", "heraldyx", "idryx", "mockryx", "qryx",
	"scopyx", "tokenfuse", "typryx", "vouchryx", "verdryx", "wardryx",
}

// exceptions is the measured set of files whose stem is not their source, or
// that carry more than one. Every row names how it was measured.
//
//   - tokenfuse-cloud, tokenfuse-mcp: the control plane and the MCP broker are
//     separate processes that append to their OWN files (two appenders on one
//     file is a race with no lock), and all three tokenfuse binaries build the
//     envelope through one crate whose SOURCE constant is `tokenfuse`
//     (tokenfuse crates/core/src/agent_event.rs; stack-single compose.yaml,
//     stack-k8s manifests 00-base and 52, stack-up up.sh).
//   - demo: `taipan demo` writes one synthetic file whose lines are attributed
//     to six planes (taipan src/commands/demo.rs, SAMPLE_EVENTS), the one
//     legitimate multi-source file in the estate.
//
// Not listed on purpose: scopyx's and heraldyx's own journals (`events.ndjson`
// on scopyx's own volume in two launchers, `sent.ndjson` beside heraldyx's
// state). They are not on the shared bus and no launcher points a reader at
// them; a reader that is pointed at one declares it with IDRYX_STREAMS.
var exceptions = map[string][]string{
	"tokenfuse-cloud": {"tokenfuse"},
	"tokenfuse-mcp":   {"tokenfuse"},
	"demo":            {"engram", "mockryx", "qryx", "tokenfuse", "verdryx", "wardryx"},
}

// Policy maps a stream stem to the sources it may carry.
type Policy struct {
	allowed map[string]map[string]bool
}

// Default is the convention plus the measured exception table.
func Default() Policy {
	p := Policy{allowed: map[string]map[string]bool{}}
	for _, s := range knownSources {
		p.add(s, s)
	}
	for stem, sources := range exceptions {
		for _, s := range sources {
			p.add(stem, s)
		}
	}
	return p
}

func (p *Policy) add(stem, source string) {
	if p.allowed == nil {
		p.allowed = map[string]map[string]bool{}
	}
	if p.allowed[stem] == nil {
		p.allowed[stem] = map[string]bool{}
	}
	p.allowed[stem][source] = true
}

// Extend returns a copy of p with the operator's declarations added. A
// declaration adds to a stem's set and never removes from it: an operator can
// widen what the box accepts, and cannot narrow what a producer is known to
// write.
func (p Policy) Extend(extra map[string][]string) Policy {
	out := Policy{allowed: map[string]map[string]bool{}}
	for stem, set := range p.allowed {
		for s := range set {
			out.add(stem, s)
		}
	}
	for stem, sources := range extra {
		for _, s := range sources {
			out.add(stem, s)
		}
	}
	return out
}

// Check decides one line: the stem of the file it was read from, and the
// source it claims.
func (p Policy) Check(stem, source string) Verdict {
	if set, declared := p.allowed[stem]; declared {
		if set[source] {
			return Allowed
		}
		return Foreign
	}
	if source == stem {
		return AllowedUnknownStem
	}
	return Foreign
}

// AllowedFor lists, sorted, the sources the stem may carry: its declared set,
// or just the stem itself for a stream nothing declares. For a message that
// has to say what WOULD have been accepted.
func (p Policy) AllowedFor(stem string) []string {
	set, declared := p.allowed[stem]
	if !declared {
		return []string{stem}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Stem is the stream name of a file: its base name without the `.ndjson`
// suffix, or without whatever other extension it has.
func Stem(path string) string {
	base := filepath.Base(path)
	if t := strings.TrimSuffix(base, ".ndjson"); t != base {
		return t
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// name is the shape of a stem or a source in an operator declaration. Wider
// than the registry's `[a-z0-9-]+` so a box with its own naming is not
// refused, and narrower than anything that could carry a separator or a
// control character into a message.
var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidName reports whether s can appear in a declaration, as a stem or as a
// source. A caller building a hint of the form `stem=source` out of text a
// producer wrote uses it to refuse to print a hint that could not be typed
// back in.
func ValidName(s string) bool { return name.MatchString(s) }

// ParseExtra reads the operator's declaration: comma-separated entries, each
// `stem=source|source`. For example `events=tokenfuse|wardryx,mix=a|b`.
//
// An empty string is no declaration. A malformed entry is an error naming it,
// not a silent skip: the rule fails closed, so an entry the process ignored
// would read as a producer that stopped being heard.
func ParseExtra(spec string) (map[string][]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := map[string][]string{}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		stem, list, ok := strings.Cut(entry, "=")
		stem = strings.TrimSpace(stem)
		if !ok || !name.MatchString(stem) {
			return nil, fmt.Errorf("stream declaration %q: want stem=source|source", entry)
		}
		var sources []string
		for _, s := range strings.Split(list, "|") {
			s = strings.TrimSpace(s)
			if !name.MatchString(s) {
				return nil, fmt.Errorf("stream declaration %q: %q is not a source name", entry, s)
			}
			sources = append(sources, s)
		}
		out[stem] = append(out[stem], sources...)
	}
	return out, nil
}
