// Package tokenfuse ingests agent-event NDJSON: one shared envelope shape,
// taipanbox.dev/agent-event (agent-passport SPEC §6), written by every
// producer on the agent-event bus (TokenFuse, Wardryx, Mockryx, Verdryx, and
// any future emitter). It is a hybrid connector: unlike the single-purpose
// event or inventory sources, it produces both agent/human identities (from
// agent_id and on_behalf_of) and behavioral events in one pass, since the
// two live in the same envelope. Parsing is strictly deterministic and
// read-only: it never mutates anything, and a malformed line never aborts
// the run (it is counted in Report and the rest of the file is still
// processed), per the spec's forward-compatibility rule (§6.1, §7).
//
// The package kept the name "tokenfuse" for backward compatibility (it began
// as a TokenFuse-only connector, before Wardryx/Mockryx/Verdryx joined the
// same bus), but Parse and Load are fully generic: every identity's and
// every event's Source is read from the envelope's own `source` field,
// never assumed from whichever --load prefix selected this loader. cmd/idryx's
// --load tokenfuse:/wardryx:/mockryx:/verdryx: prefixes all resolve to this
// same connector for exactly that reason (see populate() and
// agentBusSources in cmd/idryx/main.go): the parsing is identical, so a
// TokenFuse file loaded via --load wardryx:<path> by mistake still comes
// out labeled "tokenfuse" (from its own envelopes), and a Wardryx file
// loaded via --load tokenfuse:<path> still comes out labeled "wardryx".
// Nothing here special-cases any one producer name.
package tokenfuse

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// knownTypes is the v0.1 tokenfuse event-type registry (SPEC §6.2), for
// tokenfuse's own event types specifically, not the bus as a whole. The map
// values equal their keys by construction (model.EventType is a string type
// whose tokenfuse constants match the wire values verbatim); the map exists
// so callers can name these types (e.g. in future detectors) without
// stringly-typed literals scattered around, and so Report can tell a known
// type from one outside the v0.1 registry. A type from a different bus
// producer (e.g. wardryx's policy_deny, mockryx's sim_finding, verdryx's
// quality_drift) is never in this map by design: it falls through the same
// generic, tolerant path as an unrecognized tokenfuse type below, carried
// through as a model.EventType(string), never dropped and never an error.
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
// v0.1 registry (still ingested, just tallied for visibility).
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

// Parse decodes one NDJSON blob of taipanbox.dev/agent-event envelopes
// (schema v0.1 or v0.2; agent-stack-go/event's Unmarshal accepts either)
// into identities and behavioral events.
//
//   - Each event with an agent_id not seen earlier in this blob yields an
//     Identity{Type: IdentityAgent, ID: agent_id, Source: env.Source}. The
//     Source always comes from the envelope's own `source` field (e.g.
//     "tokenfuse", "wardryx", "mockryx", "verdryx"); Parse never assumes or
//     hardcodes which producer wrote the file.
//   - Every on_behalf_of entry becomes part of that agent's delegation chain
//     (model.Identity.OnBehalfOf, agent-passport SPEC §5). Entries with the
//     user:// scheme also create an IdentityHuman identity (ID = the URI,
//     Source = env.Source) the first time they're seen, when not already
//     produced.
//   - Every well-formed line also yields a model.Event, also carrying
//     Source = env.Source, so it feeds the graph's normal behavioral
//     pipeline (baselines, detectors). Types in the tokenfuse v0.1/v0.2
//     registry (§6.2) map to their named model.EventType constant; any
//     other type, whether an unrecognized tokenfuse type or a type from a
//     different bus producer entirely, is carried through as-is
//     (model.EventType is just a string, so this is tolerant by
//     construction, never an error).
//
// A line that isn't valid JSON, or is missing a required envelope field
// (schema, ts, source, type, agent_id, per SPEC §6.1 and
// agentstack/event.Unmarshal), or has an unparseable ts, is counted in
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

		env, err := event.Unmarshal(line)
		if err != nil {
			rep.Malformed++
			continue
		}
		// event.Unmarshal only checks that ts is non-empty; the RFC3339
		// shape check stays here, unchanged from before.
		ts, err := time.Parse(time.RFC3339, env.TS)
		if err != nil {
			rep.Malformed++
			continue
		}

		if !seenAgents[env.AgentID] {
			seenAgents[env.AgentID] = true
			identities = append(identities, model.Identity{
				ID:   env.AgentID,
				Type: model.IdentityAgent,
				// From the envelope's own field, never a hardcoded literal
				// (review finding L3): a wardryx/mockryx/verdryx file must
				// not come out mislabeled "tokenfuse".
				Source:     env.Source,
				OnBehalfOf: append([]string(nil), env.OnBehalfOf...),
			})
		}

		// Human principals named in the chain become their own identity the
		// first time they're seen, when not already produced elsewhere.
		for _, p := range env.OnBehalfOf {
			if strings.HasPrefix(p, "user://") && !seenHumans[p] {
				seenHumans[p] = true
				identities = append(identities, model.Identity{
					ID:   p,
					Type: model.IdentityHuman,
					// Same fix as the agent identity above: from the
					// envelope, never hardcoded.
					Source: env.Source,
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
			// From the envelope's own field, same fix as the identities
			// above: lets events from several bus producers mix correctly
			// on one agent's Events slice (e.g. tokenfuse spend events
			// alongside wardryx policy events for the same agent_id).
			Source: env.Source,
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
		data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument/glob, not untrusted input
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
