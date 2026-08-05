package ingest

// Report summarizes one connector parse call: how many records were read and
// how many were skipped for being malformed (e.g. a timestamp that does not
// parse as RFC3339). Mirrors tokenfuse.Report and passport.Report's
// shape/intent: a connector reading attacker-influenced input (SECURITY.md
// invariant 3: "every connector input... is attacker-influenced data") must
// never drop a record without a caller-visible count of what it dropped. For
// an identity plane, a silently truncated log is a detection gap nobody can
// see. The zero value is a legitimate "nothing was malformed" report.
type Report struct {
	Records   int
	Malformed int
}
