package tokenfuse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// chainedStream returns an NDJSON stream of n events, each carrying the
// SPEC 6.5 prev_hash of the line before it, written through the shared
// module's own ChainedWriter so the bytes under test are produced by the
// same code a real bus producer uses.
func chainedStream(t *testing.T, n int) (path string, lines []string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "chained.ndjson")
	w, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("new chained writer: %v", err)
	}
	for i := 0; i < n; i++ {
		e := event.Event{
			Schema:  event.SchemaV02,
			TS:      "2026-08-05T10:0" + string(rune('0'+i)) + ":00Z",
			Source:  "tokenfuse",
			Type:    "spend_spike",
			AgentID: "agent://acme.example/bot",
		}
		if err := w.Write(e); err != nil {
			t.Fatalf("write event %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stream.ndjson")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestChainIntactStreamVerifies is the positive case: a stream whose
// prev_hash chain holds must come back verified, with every non-head event
// counted as chained and no break. Without this, "intact" and "nobody
// checked" are the same silence.
func TestChainIntactStreamVerifies(t *testing.T) {
	path, lines := chainedStream(t, 4)
	if len(lines) != 4 {
		t.Fatalf("fixture wrote %d lines, want 4", len(lines))
	}

	_, _, rep, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !rep.Chain.Verified {
		t.Fatal("Chain.Verified = false: an unchecked stream must not read as an intact one")
	}
	if !rep.Chain.Present() {
		t.Error("Chain.Present() = false on a stream that carries prev_hash values")
	}
	if got := rep.Chain.Chained; got != 3 {
		t.Errorf("Chain.Chained = %d, want 3 (4 events, the first is the head)", got)
	}
	if got := rep.Chain.Heads; got != 1 {
		t.Errorf("Chain.Heads = %d, want 1", got)
	}
	if n := len(rep.Chain.Breaks); n != 0 {
		t.Errorf("Chain.Breaks = %d, want 0: %+v", n, rep.Chain.Breaks)
	}
	if !rep.Chain.Intact() {
		t.Error("Chain.Intact() = false on a stream with no breaks")
	}
}

// TestChainTamperedLineIsReportedWithItsPosition edits the payload of one
// line in a valid chain. The edit changes that line's hash, so the link
// carried by the line AFTER it no longer matches: the break is reported at
// the following physical line number, which is the first line the stream
// can prove was not the one written.
func TestChainTamperedLineIsReportedWithItsPosition(t *testing.T) {
	_, lines := chainedStream(t, 4)
	lines[1] = strings.Replace(lines[1], `"type":"spend_spike"`, `"type":"budget_exhausted"`, 1)
	if !strings.Contains(lines[1], "budget_exhausted") {
		t.Fatal("tamper did not apply, the fixture shape changed")
	}
	path := writeLines(t, lines)

	_, events, rep, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(rep.Chain.Breaks); n != 1 {
		t.Fatalf("Chain.Breaks = %d, want exactly 1: %+v", n, rep.Chain.Breaks)
	}
	b := rep.Chain.Breaks[0]
	if b.Line != 3 {
		t.Errorf("break reported at line %d, want 3 (the line after the edited one)", b.Line)
	}
	if b.File != path {
		t.Errorf("break File = %q, want %q", b.File, path)
	}
	if b.Expected == "" || b.Found == "" || b.Expected == b.Found {
		t.Errorf("break must carry both the expected and the found hash, got %+v", b)
	}
	if rep.Chain.Intact() {
		t.Error("Chain.Intact() = true on a tampered stream")
	}
	// Tamper-evidence is not a reason to discard evidence: every line is
	// still ingested.
	if len(events) != 4 {
		t.Errorf("events = %d, want 4: a broken chain must not drop the stream", len(events))
	}
}

// TestChainDroppedLineIsReportedWithItsPosition covers the truncation shape:
// a line removed from the middle of a chain leaves the next line's prev_hash
// pointing at an event that is no longer there.
func TestChainDroppedLineIsReportedWithItsPosition(t *testing.T) {
	_, lines := chainedStream(t, 4)
	kept := append(append([]string{}, lines[:2]...), lines[3])
	path := writeLines(t, kept)

	_, _, rep, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(rep.Chain.Breaks); n != 1 {
		t.Fatalf("Chain.Breaks = %d, want exactly 1: %+v", n, rep.Chain.Breaks)
	}
	if got := rep.Chain.Breaks[0].Line; got != 3 {
		t.Errorf("break reported at line %d, want 3 (the line that followed the dropped one)", got)
	}
}

// TestChainRestartIsNotABreak holds the spec's own rule (SPEC 6.5,
// agent-stack-go invariant 7): prev_hash is optional, so a stream may
// legally restart, for example after a process restart that could not
// resume. A restart is a second chain head, never a break.
func TestChainRestartIsNotABreak(t *testing.T) {
	_, first := chainedStream(t, 2)
	_, second := chainedStream(t, 2)
	path := writeLines(t, append(append([]string{}, first...), second...))

	_, _, rep, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(rep.Chain.Breaks); n != 0 {
		t.Errorf("a legal chain restart was reported as %d break(s): %+v", n, rep.Chain.Breaks)
	}
	if got := rep.Chain.Heads; got != 2 {
		t.Errorf("Chain.Heads = %d, want 2 (the stream head plus one restart)", got)
	}
	if !rep.Chain.Intact() {
		t.Error("Chain.Intact() = false on a stream whose only anomaly is a legal restart")
	}
}

// TestChainAbsentIsNotIntact is the distinction the operator needs: the
// bundled fixture carries no prev_hash at all, so the chain was checked and
// found absent. That is neither a break nor a clean bill of health.
func TestChainAbsentIsNotIntact(t *testing.T) {
	data, err := os.ReadFile("testdata/events.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	_, _, rep := Parse(data)
	if !rep.Chain.Verified {
		t.Error("Chain.Verified = false: verification runs over every stream, chained or not")
	}
	if rep.Chain.Present() {
		t.Error("Chain.Present() = true on a fixture that carries no prev_hash")
	}
	if len(rep.Chain.Breaks) != 0 {
		t.Errorf("an unchained stream must not report breaks: %+v", rep.Chain.Breaks)
	}
}

// TestChainVerificationSurvivesMalformedLines keeps the connector's
// existing contract intact: a malformed line is counted and skipped, never
// fatal, and it does not turn the following event into a break (there is no
// previous event to hash, so it is unverifiable instead).
func TestChainVerificationSurvivesMalformedLines(t *testing.T) {
	_, lines := chainedStream(t, 3)
	withGarbage := []string{lines[0], "{not json", lines[1], lines[2]}
	path := writeLines(t, withGarbage)

	_, events, rep, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rep.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", rep.Malformed)
	}
	if len(events) != 3 {
		t.Errorf("events = %d, want 3", len(events))
	}
	if n := len(rep.Chain.Breaks); n != 0 {
		t.Errorf("a malformed line must not be reported as a chain break: %+v", rep.Chain.Breaks)
	}
	if got := len(rep.Chain.Unverifiable); got != 1 {
		t.Errorf("Chain.Unverifiable = %d, want 1 (the event after the malformed line)", got)
	}
}

// TestChainReportMergesAcrossFiles: Load may read a glob, and a break has to
// name the file it is in, not just a line number that means nothing without
// one.
func TestChainReportMergesAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	_, clean := chainedStream(t, 2)
	_, broken := chainedStream(t, 3)
	broken[1] = strings.Replace(broken[1], `"type":"spend_spike"`, `"type":"sustained_loop"`, 1)

	cleanPath := filepath.Join(dir, "a.ndjson")
	brokenPath := filepath.Join(dir, "b.ndjson")
	if err := os.WriteFile(cleanPath, []byte(strings.Join(clean, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(brokenPath, []byte(strings.Join(broken, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, rep, err := Load(filepath.Join(dir, "*.ndjson"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := len(rep.Chain.Breaks); n != 1 {
		t.Fatalf("Chain.Breaks = %d, want 1: %+v", n, rep.Chain.Breaks)
	}
	if got := rep.Chain.Breaks[0].File; got != brokenPath {
		t.Errorf("break File = %q, want %q", got, brokenPath)
	}
	if got := rep.Chain.Chained; got != 2 {
		t.Errorf("Chain.Chained = %d, want 2 (one verified link in each file)", got)
	}
}
