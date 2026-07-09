// Package passport ingests Agent Passport documents (agent-passport SPEC
// §4): one small, static JSON file per agent describing its identity,
// owning team, runtime, static provisioning parent, and attestation
// posture. Unlike the tokenfuse connector — which reads a stream of
// behavioral events observed over time — a Passport is capture-only
// metadata: idryx reads a directory (or glob) of these documents once and
// produces exactly one model.Identity per file, never an event. Parsing is
// strictly deterministic and read-only; a malformed passport file is
// counted and skipped, never fatal, mirroring the tokenfuse connector's
// Report pattern (SPEC §7: unknown/absent fields are tolerated, not
// errors — except the three fields SPEC §4.1 requires).
package passport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// requiredSchema is the only Passport schema version this connector
// understands (SPEC §4, §8.4). A document declaring a different (or
// missing) schema string is treated as malformed rather than best-effort
// parsed — a future schema version needs its own connector logic, not a
// silent guess at compatibility.
const requiredSchema = "taipanbox.dev/agent-passport/v0.1"

// document is the wire shape of one Passport JSON file (SPEC §4;
// schemas/agent-passport.schema.json). Only the fields idryx maps into the
// graph are decoded; `display_name`, `labels`, `created_at`, and any other
// field are ignored — the schema itself declares additionalProperties:
// true, so an unrecognized field must never be an error.
type document struct {
	Schema      string `json:"schema"`
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Runtime     string `json:"runtime"`
	Parent      string `json:"parent"`
	Attestation struct {
		Method string `json:"method"`
	} `json:"attestation"`
}

// Report summarizes one Load call: how many passport files were attempted
// and how many were malformed and skipped. Mirrors tokenfuse.Report's
// shape/intent for the same reason: a batch of external, operator-supplied
// files must never abort on one bad entry, but the caller still deserves a
// visible count of what was skipped.
type Report struct {
	Files     int
	Malformed int
}

// Parse decodes one Passport JSON document into a model.Identity. It
// returns an error — meaning the file is malformed to the caller — only
// when the document isn't valid JSON, its schema isn't requiredSchema, or
// either of the SPEC §4.1-required fields beyond schema (id, owner) is
// missing. Every other field is optional, per SPEC §4.1.
func Parse(data []byte) (model.Identity, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return model.Identity{}, fmt.Errorf("invalid json: %w", err)
	}
	if doc.Schema != requiredSchema {
		return model.Identity{}, fmt.Errorf("unsupported schema %q, want %q", doc.Schema, requiredSchema)
	}
	if doc.ID == "" || doc.Owner == "" {
		return model.Identity{}, fmt.Errorf("missing required field(s): id and owner are required")
	}
	return model.Identity{
		ID:          doc.ID,
		Type:        model.IdentityAgent,
		Source:      "passport",
		Owner:       doc.Owner,
		Runtime:     doc.Runtime,
		Parent:      doc.Parent,
		Attestation: doc.Attestation.Method,
	}, nil
}

// Load reads every Passport document reachable from dirOrGlob and parses
// each with Parse.
//
// dirOrGlob is, in order of precedence:
//  1. an existing directory — every "*.json" file directly inside it
//     (non-recursive) is read;
//  2. a glob pattern such as "passports/*.json";
//  3. otherwise tried as a literal file path, so a genuinely missing input
//     still produces a clear I/O error rather than a silently empty batch.
//
// Files are processed in sorted-path order for a deterministic result. A
// file that fails Parse is counted in Report.Malformed and skipped — it
// never aborts the rest of the batch. Load only returns an error for I/O
// failures (bad glob pattern, unreadable directory/file); content problems
// are tolerated and surfaced in the returned Report instead, per Parse's
// contract.
//
// A duplicate agent id across two files (the same agent accidentally
// shipped in two passports) keeps only the first occurrence in sorted-path
// order, so Load's output is deterministic and idryx never carries two
// Identity records for one id from this connector.
func Load(dirOrGlob string) ([]model.Identity, Report, error) {
	matches, err := resolve(dirOrGlob)
	if err != nil {
		return nil, Report{}, err
	}
	sort.Strings(matches)

	rep := Report{}
	seen := map[string]bool{}
	var identities []model.Identity
	for _, path := range matches {
		data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument/glob/directory listing, not untrusted input
		if err != nil {
			return nil, Report{}, fmt.Errorf("passport: read %s: %w", path, err)
		}
		rep.Files++
		id, err := Parse(data)
		if err != nil {
			rep.Malformed++
			continue
		}
		if seen[id.ID] {
			continue
		}
		seen[id.ID] = true
		identities = append(identities, id)
	}
	return identities, rep, nil
}

// resolve expands dirOrGlob into the list of passport files to read, per
// Load's documented precedence.
func resolve(dirOrGlob string) ([]string, error) {
	if info, err := os.Stat(dirOrGlob); err == nil && info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(dirOrGlob, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("passport: bad directory %q: %w", dirOrGlob, err)
		}
		return matches, nil
	}
	matches, err := filepath.Glob(dirOrGlob)
	if err != nil {
		return nil, fmt.Errorf("passport: bad glob %q: %w", dirOrGlob, err)
	}
	if len(matches) == 0 {
		// Not a glob (or a glob that matched nothing): try it as a literal
		// path so a missing file still produces a clear I/O error.
		matches = []string{dirOrGlob}
	}
	return matches, nil
}
