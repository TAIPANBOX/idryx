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
	"github.com/TAIPANBOX/agent-stack-go/passport"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// knownTypes is the subset of the SPEC §6.2 registry that idryx names in code,
// rather than the bus as a whole. The map values equal their keys by
// construction (model.EventType is a string type whose constants match the wire
// values verbatim); the map exists so callers can name these types without
// stringly-typed literals scattered around, and so Report can tell a type idryx
// reasons about from one it merely carries. A type from a producer nothing here
// reasons about (wardryx's policy_deny, mockryx's sim_finding, verdryx's
// quality_drift) is never in this map by design: it falls through the same
// generic, tolerant path as an unrecognized type below, carried through as a
// model.EventType(string), never dropped and never an error.
//
// scopyx's two joined the map when a detector started reading them
// (unrouted_egress, which needs to tell a refusal from a fetch). Before that
// they were carried through correctly and counted as unknown on every load,
// which is what this map is for: the count means "outside what idryx names",
// and a type a detector reads is inside it.
var knownTypes = map[string]model.EventType{
	"budget_exhausted": model.EventBudgetExhausted,
	"sustained_loop":   model.EventSustainedLoop,
	"spend_spike":      model.EventSpendSpike,
	"fanout_explosion": model.EventFanoutExplosion,
	"breaker_tripped":  model.EventBreakerTripped,
	"dlp_block":        model.EventDLPBlock,
	"taint_block":      model.EventTaintBlock,
	"mcp_drift":        model.EventMCPDrift,
	"web_fetch":        model.EventWebFetch,
	"web_blocked":      model.EventWebBlocked,
}

// Report summarizes one Parse or Load call: how many lines were read, how
// many were malformed and skipped, which event types fell outside the
// v0.1 registry (still ingested, just tallied for visibility), and the
// state of the stream's SPEC 6.5 prev_hash integrity chain.
type Report struct {
	Lines        int
	Malformed    int
	UnknownTypes map[string]int
	Chain        Chain
}

// ChainBreak is one genuine prev_hash violation: an event whose prev_hash is
// present and does not match the hash of the event on the line before it. It
// carries the file and the 1-based PHYSICAL line number (blank lines
// included, so `sed -n '<line>p' <file>` shows the offending record), because
// a line number without a file means nothing when Load read a glob.
type ChainBreak struct {
	File     string
	Line     int
	Expected string // the hash of the preceding event, i.e. what prev_hash should have been
	Found    string // what the line actually carried
}

// Chain is the verdict of the SPEC 6.5 prev_hash check over the stream, run
// on every ingest by agent-stack-go's own event.VerifyChain (invariant 3:
// the shared module is the single source of the wire types, and of the
// hashing rule with them).
//
// The three states an operator has to be able to tell apart are all
// representable here, which is the whole point of the type:
//
//   - Verified && Present() && Intact(): the log was checked and holds.
//   - Verified && !Present(): checked, and the producer maintains no chain,
//     so nothing about tampering is known either way. prev_hash is optional
//     per spec, so this is legal and common, and it is NOT a clean bill of
//     health.
//   - !Verified: nobody checked. Only possible on a Report that never went
//     through Parse/Load.
type Chain struct {
	// Verified reports that the check ran over the whole stream.
	Verified bool
	// Chained is the number of events whose prev_hash matched the event on
	// the line before them.
	Chained int
	// Heads is the number of events carrying no prev_hash: one for the
	// stream head, plus one per legal restart (SPEC 6.5 keeps prev_hash
	// optional, so a producer that could not resume its chain after a
	// process restart is within the spec). A restart is never a break.
	Heads int
	// Unverifiable holds the physical line numbers of events whose prev_hash
	// could not be checked because there was nothing checkable before them:
	// the stream opens mid-chain (a rotated segment), or the preceding line
	// was malformed. Reported, never accused of being a break.
	Unverifiable []int
	// Breaks holds the genuine mismatches.
	Breaks []ChainBreak
}

// Present reports whether the stream carries a prev_hash chain at all. A
// stream of chain heads only (no event referencing another) carries none.
func (c Chain) Present() bool {
	return c.Chained > 0 || len(c.Unverifiable) > 0 || len(c.Breaks) > 0
}

// Intact reports whether the chain was checked and no genuine break was
// found. It is deliberately false on an unverified Report: silence must
// never read as a clean bill of health.
func (c Chain) Intact() bool { return c.Verified && len(c.Breaks) == 0 }

func newReport() Report {
	return Report{UnknownTypes: map[string]int{}}
}

func (r *Report) merge(o Report) {
	r.Lines += o.Lines
	r.Malformed += o.Malformed
	for t, n := range o.UnknownTypes {
		r.UnknownTypes[t] += n
	}
	r.Chain.merge(o.Chain)
}

// merge folds one file's chain verdict into an aggregate over several files.
// Verified is an AND: an aggregate is only "checked" if every file in it was.
func (c *Chain) merge(o Chain) {
	c.Verified = c.Verified && o.Verified
	c.Chained += o.Chained
	c.Heads += o.Heads
	c.Unverifiable = append(c.Unverifiable, o.Unverifiable...)
	c.Breaks = append(c.Breaks, o.Breaks...)
}

// verifyChain runs the shared module's SPEC 6.5 verifier over one stream and
// maps its report onto Chain, stamping file onto every break.
//
// It is a second pass over the same bytes, on purpose: the hashing rule
// lives in agent-stack-go and re-implementing it inline in Parse's own loop
// would put a second copy of the wire contract in this repository, which is
// exactly the drift AGENTS.md invariant 3 exists to prevent.
func verifyChain(data []byte, file string) Chain {
	rep, err := event.VerifyChain(bytes.NewReader(data))
	if err != nil {
		// The only error VerifyChain returns is the scanner's, on a line
		// longer than its 4 MiB buffer. Parse's own scanner has the same
		// limit and would skip that line too, so the honest answer is
		// "this stream was not fully checked".
		return Chain{Verified: false}
	}
	c := Chain{
		Verified:     true,
		Chained:      rep.Chained,
		Heads:        len(rep.HeadLines),
		Unverifiable: rep.Unverifiable,
	}
	for _, b := range rep.Breaks {
		c.Breaks = append(c.Breaks, ChainBreak{
			File:     file,
			Line:     b.Line,
			Expected: b.Expected,
			Found:    b.Found,
		})
	}
	return c
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
//
// Every stream is also checked against the SPEC §6.5 prev_hash integrity
// chain, and the verdict is returned in Report.Chain. A broken chain does
// NOT stop the ingest and does not drop a single event: see the reasoning
// on Chain and in cmd/idryx's reportTokenFuse. Idryx exists to notice
// tampering, and refusing to ingest a stream that shows evidence of it
// would hand an attacker a way to delete every finding in the file by
// editing one line of it.
func Parse(data []byte) ([]model.Identity, []model.Event, Report) {
	return parse(data, "")
}

// parse is Parse with the file name the data came from, so a chain break
// can name it. Empty when the caller had only bytes (Parse's own contract).
func parse(data []byte, file string) ([]model.Identity, []model.Event, Report) {
	rep := newReport()
	rep.Chain = verifyChain(data, file)
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
			// A CLAIMED subject is not typed as an established agent, and the
			// same string arriving by two doors is why this branch exists.
			//
			// agent-passport SPEC 3.3 made `claimed:agent://...` a wire form on
			// 2026-08-10, so this connector started meeting it. The sensor
			// creates the same id through graph.AddEvent, where the type stays
			// unset; this loop was creating it as a governed agent. One id, two
			// kinds of node, decided by which door it came through.
			//
			// What that cost: `bom_incomplete` and `orphaned_nhi` select on the
			// type, so idryx reading its OWN journal back reported a missing
			// owner, runtime and attestation for a name nobody issued, and no
			// mapped owner for a name a process wrote about itself. An
			// Agent-BOM cannot be incomplete for something that was never
			// issued.
			//
			// It is still INGESTED, on purpose. A claim on the bus is a real
			// observation somebody made, and the id is byte-identical to the
			// sensor's, so the two merge into one node and the claim-family
			// detectors reason over it. What it must not do is arrive dressed
			// as an identity the organisation established.
			kind := model.IdentityAgent
			if passport.IsClaimedSubject(env.AgentID) {
				kind = model.IdentityType("")
			}
			identities = append(identities, model.Identity{
				ID:   env.AgentID,
				Type: kind,
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
//
// Each file's prev_hash chain is verified on its own and the verdicts are
// merged: line numbers are per-file, which is why every ChainBreak carries
// the file it was found in. Two files are two chains, so the second file
// starting a fresh chain is a head, not a break.
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
	// The aggregate starts as checked and each file ANDs its own verdict in
	// (Chain.merge). An aggregate over zero files cannot happen here: a glob
	// that matches nothing falls back to the literal path above, and an
	// unreadable file returns before any merge.
	rep.Chain.Verified = true
	seenAgents := map[string]bool{}
	seenHumans := map[string]bool{}
	var identities []model.Identity
	var events []model.Event

	for _, path := range matches {
		data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument/glob, not untrusted input
		if err != nil {
			return nil, nil, Report{}, fmt.Errorf("tokenfuse: read %s: %w", path, err)
		}
		ids, evs, r := parse(data, path)
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
