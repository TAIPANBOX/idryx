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
//
// The directory/glob walk itself (resolve, sort, dedupe by first-seen id)
// is agent-stack-go/passport.LoadDir; this package supplies only the
// Passport -> model.Identity parse step.
package passport

import (
	"fmt"

	agentpassport "github.com/TAIPANBOX/agent-stack-go/passport"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// Report summarizes one Load call: how many passport files were attempted
// and how many were malformed and skipped. Mirrors tokenfuse.Report's
// shape/intent for the same reason: a batch of external, operator-supplied
// files must never abort on one bad entry, but the caller still deserves a
// visible count of what was skipped.
type Report = agentpassport.Report

// Parse decodes one Passport JSON document into a model.Identity, using the
// shared wire type from agent-stack-go/passport instead of a private,
// hand-rolled struct. It returns an error, meaning the file is malformed to
// the caller, whenever agentpassport.Parse does: the document isn't valid
// JSON, its schema isn't the supported taipanbox.dev/agent-passport/v0.1, id
// or owner is missing, or id is not a well-formed agent:// URI.
//
// That last check is new relative to Idryx's previous hand-rolled decode,
// which treated id as an opaque string and never validated its shape.
// agent-stack-go validates it, so a passport whose id is not a well-formed
// agent:// URI now counts as malformed here where it previously did not.
// Load already treats every Parse error the same way (count in
// Report.Malformed, skip, never fatal), so this only tightens what is
// accepted; it does not change the tolerant contract.
func Parse(data []byte) (model.Identity, error) {
	doc, err := agentpassport.Parse(data)
	if err != nil {
		return model.Identity{}, fmt.Errorf("passport: %w", err)
	}
	attestation := ""
	if doc.Attestation != nil {
		attestation = doc.Attestation.Method
	}
	return model.Identity{
		ID:          doc.ID,
		Type:        model.IdentityAgent,
		Source:      "passport",
		Owner:       doc.Owner,
		Runtime:     doc.Runtime,
		Parent:      doc.Parent,
		Attestation: attestation,
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
	return agentpassport.LoadDir(dirOrGlob, Parse, func(id model.Identity) string { return id.ID })
}
