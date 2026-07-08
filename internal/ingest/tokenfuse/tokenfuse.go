// Package tokenfuse ingests TokenFuse behavioral events for AI agents: NDJSON
// files of taipanbox.dev/agent-event/v0.1 envelopes (agent-passport SPEC §6).
// It is a hybrid connector — unlike the single-purpose event or inventory
// sources, it produces both agent/human identities (from agent_id and
// on_behalf_of) and behavioral events in one pass, since the two live in the
// same envelope. Parsing is strictly deterministic and read-only: it never
// mutates anything, and a malformed line never aborts the run — it is
// counted in Report and the rest of the file is still processed, per the
// spec's forward-compatibility rule (§6.1, §7).
package tokenfuse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// envelope is the wire shape of one taipanbox.dev/agent-event NDJSON line.
// Only the fields idryx needs are decoded; `data` and any other top-level
// field are ignored, per SPEC §6.1's forward-compatibility rule — a producer
// adding fields must never break this connector.
type envelope struct {
	Schema     string   `json:"schema"`
	TS         string   `json:"ts"`
	Source     string   `json:"source"`
	Type       string   `json:"type"`
	Severity   string   `json:"severity"`
	AgentID    string   `json:"agent_id"`
	RunID      string   `json:"run_id"`
	OnBehalfOf []string `json:"on_behalf_of"`
}

// knownTypes is the v0.1 tokenfuse event-type registry (SPEC §6.2). The map
// values equal their keys by construction (model.EventType is a string type
// whose tokenfuse constants match the wire values verbatim) — the map exists
// so callers can name these types (e.g. in future detectors) without
// stringly-typed literals scattered around, and so Report can tell a known
// type from one outside the v0.1 registry.
var knownTypes = map[string]model.EventType{
	"budget_exhausted": model.EventBudgetExhausted,
	"sustained_loop":   model.EventSustainedLoop,
	"spend_spike":      model.EventSpendSpike,
	"fanout_explosion": model.EventFanoutExplosion,
	"breaker_tripped":  model.EventBreakerTripped,
	"dlp_block":        model.EventDLPBlock,
	"taint_block":      model.EventTaintBlock,
	"mcp_drift":        model.EventMCPDrift,
}

// Report summarizes one Parse or Load call: how many lines were read, how
// many were malformed and skipped, and which event types fell outside the
// v0.1 registry (still ingested — just tallied for visibility).
type Report struct {
	Lines        int
	Malformed    int
	UnknownTypes map[string]int
}

func newReport() Report {
	return Report{UnknownTypes: map[string]int{}}
}

func (r *Report) merge(o Report) {
	r.Lines += o.Lines
	r.Malformed += o.Malformed
	for t, n := range o.UnknownTypes {
		r.UnknownTypes[t] += n
	}
}

// Parse decodes one NDJSON blob of taipanbox.dev/agent-event/v0.1 envelopes
// into identities and behavioral events.
//
//   - Each event with an agent_id not seen earlier in this blob yields an
//     Identity{Type: IdentityAgent, ID: agent_id, Source: "tokenfuse"}.
//   - Every on_behalf_of entry becomes part of that agent's delegation chain
//     (model.Identity.OnBehalfOf, agent-passport SPEC §5). Entries with the
//     user:// scheme also create an IdentityHuman identity (ID = the URI)
//     the first time they're seen, when not already produced.
//   - Every well-formed line also yields a model.Event so it feeds the
//     graph's normal behavioral pipeline (baselines, detectors). Types in
//     the v0.1 registry (§6.2) map to their named model.EventType constant;
//     any other type is carried through as-is — model.EventType is just a
//     string, so this is tolerant by construction, never an error.
//
// A line that isn't valid JSON, or is missing a required field (schema, ts,
// source, type, agent_id — §6.1), or has an unparseable ts, is counted in
// Report.Malformed and skipped; it never aborts the rest of the file.
func Parse(data []byte) ([]model.Identity, []model.Event, Report) {
	rep := newReport()
	seenAgents := map[string]bool{}
	seenHumans := map[string]bool{}
	var identities []model.Identity
	var events []model.Event

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		rep.Lines++

		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			rep.Malformed++
			continue
		}
		if env.Schema == "" || env.TS == "" || env.Source == "" || env.Type == "" || env.AgentID == "" {
			rep.Malformed++
			continue
		}
		ts, err := time.Parse(time.RFC3339, env.TS)
		if err != nil {
			rep.Malformed++
			continue
		}

		if !seenAgents[env.AgentID] {
			seenAgents[env.AgentID] = true
			identities = append(identities, model.Identity{
				ID:         env.AgentID,
				Type:       model.IdentityAgent,
				Source:     "tokenfuse",
				OnBehalfOf: append([]string(nil), env.OnBehalfOf...),
			})
		}

		// Human principals named in the chain become their own identity the
		// first time they're seen, when not already produced elsewhere.
		for _, p := range env.OnBehalfOf {
			if strings.HasPrefix(p, "user://") && !seenHumans[p] {
				seenHumans[p] = true
				identities = append(identities, model.Identity{
					ID:     p,
					Type:   model.IdentityHuman,
					Source: "tokenfuse",
				})
			}
		}

		evType, known := knownTypes[env.Type]
		if !known {
			evType = model.EventType(env.Type) // generic: pass the raw type through, never error
			rep.UnknownTypes[env.Type]++
		}
		events = append(events, model.Event{
			Time:       ts,
			IdentityID: env.AgentID,
			Type:       evType,
			Severity:   env.Severity,
		})
	}
	return identities, events, rep
}

// Load reads one or more NDJSON files matching pathOrGlob — a single file
// path or a glob pattern such as "data/*.ndjson" — and parses each with
// Parse, aggregating identities, events, and the report. Files are processed
// in sorted-path order for a deterministic result; an agent or human seen in
// an earlier file is not re-emitted as a new identity by a later one. Load
// only returns an error for I/O failures (bad glob pattern, unreadable
// file); content problems are tolerated per Parse's contract and surfaced in
// the returned Report instead.
func Load(pathOrGlob string) ([]model.Identity, []model.Event, Report, error) {
	matches, err := filepath.Glob(pathOrGlob)
	if err != nil {
		return nil, nil, Report{}, fmt.Errorf("tokenfuse: bad glob %q: %w", pathOrGlob, err)
	}
	if len(matches) == 0 {
		// Not a glob (or a glob that matched nothing): try it as a literal
		// path so a missing file still produces a clear I/O error.
		matches = []string{pathOrGlob}
	}
	sort.Strings(matches)

	rep := newReport()
	seenAgents := map[string]bool{}
	seenHumans := map[string]bool{}
	var identities []model.Identity
	var events []model.Event

	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, Report{}, fmt.Errorf("tokenfuse: read %s: %w", path, err)
		}
		ids, evs, r := Parse(data)
		for _, id := range ids {
			switch id.Type {
			case model.IdentityAgent:
				if seenAgents[id.ID] {
					continue
				}
				seenAgents[id.ID] = true
			case model.IdentityHuman:
				if seenHumans[id.ID] {
					continue
				}
				seenHumans[id.ID] = true
			}
			identities = append(identities, id)
		}
		events = append(events, evs...)
		rep.merge(r)
	}
	return identities, events, rep, nil
}
