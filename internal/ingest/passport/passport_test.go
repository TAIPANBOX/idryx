package passport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestParseValidSpiffe(t *testing.T) {
	data, err := os.ReadFile("testdata/valid_spiffe.json")
	if err != nil {
		t.Fatal(err)
	}
	id, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := model.Identity{
		ID:          "agent://acme-bank.example/support/tier1-bot",
		Type:        model.IdentityAgent,
		Source:      "passport",
		Owner:       "team-support@acme-bank.example",
		Runtime:     "langgraph",
		Parent:      "agent://acme-bank.example/support/orchestrator",
		Attestation: "spiffe-svid",
	}
	switch {
	case id.ID != want.ID, id.Type != want.Type, id.Source != want.Source,
		id.Owner != want.Owner, id.Runtime != want.Runtime,
		id.Parent != want.Parent, id.Attestation != want.Attestation:
		t.Errorf("Parse = %+v, want %+v", id, want)
	}
}

func TestParseValidAttestationNone(t *testing.T) {
	data, err := os.ReadFile("testdata/valid_none.json")
	if err != nil {
		t.Fatal(err)
	}
	id, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if id.Attestation != "none" {
		t.Errorf("Attestation = %q, want %q", id.Attestation, "none")
	}
	if id.Parent != "" {
		t.Errorf("Parent = %q, want empty (no parent field in fixture)", id.Parent)
	}
}

func TestParseValidAttestationAbsent(t *testing.T) {
	data, err := os.ReadFile("testdata/valid_unattested.json")
	if err != nil {
		t.Fatal(err)
	}
	id, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// No attestation object in the document at all: the zero value, per
	// model.Identity.Attestation's documented "unknown/none" contract.
	if id.Attestation != "" {
		t.Errorf("Attestation = %q, want empty (no attestation object in fixture)", id.Attestation)
	}
}

func TestParseMalformed(t *testing.T) {
	cases := []string{
		"testdata/malformed_missing_owner.json",
		"testdata/malformed_bad_schema.json",
		"testdata/malformed_not_json.json",
		"testdata/malformed_bad_uri.json",
	}
	for _, path := range cases {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err == nil {
			t.Errorf("Parse(%s): expected an error, got nil", path)
		}
	}
}

// TestParseRejectsMalformedAgentURI covers a behavior change introduced by
// adopting agent-stack-go/passport for the wire decode: the shared Parse
// validates that id is a well-formed agent:// URI, where Idryx's previous
// hand-rolled decode treated id as an opaque non-empty string. The fixture
// here (schema correct, id and owner both non-empty, id missing the
// agent:// scheme) is exactly the shape that the old Parse used to accept
// and the new one rejects. Load's tolerant handling (Report.Malformed,
// skip, never fatal) contains the change: nothing crashes, but this
// passport now counts as malformed instead of producing an Identity.
func TestParseRejectsMalformedAgentURI(t *testing.T) {
	data, err := os.ReadFile("testdata/malformed_bad_uri.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Error("Parse: expected an error for a non-agent:// id, got nil (stricter URI validation from agent-stack-go/passport did not apply)")
	}
}

func TestLoadDirectory(t *testing.T) {
	identities, rep, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	// 7 files on disk: 3 valid, 4 malformed (bad owner, bad schema, not
	// json, and malformed_bad_uri.json added for the agent:// URI
	// validation now enforced by agent-stack-go/passport).
	if rep.Files != 7 {
		t.Errorf("Files = %d, want 7", rep.Files)
	}
	if rep.Malformed != 4 {
		t.Errorf("Malformed = %d, want 4", rep.Malformed)
	}
	if len(identities) != 3 {
		t.Fatalf("identities = %d, want 3: %+v", len(identities), identities)
	}
	byID := map[string]model.Identity{}
	for _, id := range identities {
		byID[id.ID] = id
	}
	if _, ok := byID["agent://acme-bank.example/support/tier1-bot"]; !ok {
		t.Error("missing tier1-bot")
	}
	if _, ok := byID["agent://acme-bank.example/support/orchestrator"]; !ok {
		t.Error("missing orchestrator")
	}
	if _, ok := byID["agent://acme-bank.example/eng/ci-fixer"]; !ok {
		t.Error("missing ci-fixer")
	}
}

func TestLoadGlob(t *testing.T) {
	identities, rep, err := Load("testdata/valid_*.json")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 3 || rep.Malformed != 0 {
		t.Errorf("Files/Malformed = %d/%d, want 3/0", rep.Files, rep.Malformed)
	}
	if len(identities) != 3 {
		t.Errorf("identities = %d, want 3", len(identities))
	}
}

func TestLoadSingleFile(t *testing.T) {
	identities, rep, err := Load("testdata/valid_spiffe.json")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 || rep.Malformed != 0 || len(identities) != 1 {
		t.Errorf("Files/Malformed/identities = %d/%d/%d, want 1/0/1", rep.Files, rep.Malformed, len(identities))
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, _, err := Load("testdata/does-not-exist.json"); err == nil {
		t.Fatal("expected an error for a missing, non-glob, non-directory path")
	}
}

// TestLoadDuplicateIDFirstWins covers Load's documented dedup: two files
// naming the same agent id keep only the first occurrence in sorted-path
// order, so a directory with a duplicate is still deterministic.
func TestLoadDuplicateIDFirstWins(t *testing.T) {
	dir := t.TempDir()
	first := `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://x/dup","owner":"a@x.com","runtime":"first"}`
	second := `{"schema":"taipanbox.dev/agent-passport/v0.1","id":"agent://x/dup","owner":"a@x.com","runtime":"second"}`
	if err := os.WriteFile(filepath.Join(dir, "a-first.json"), []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b-second.json"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	identities, rep, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 2 || rep.Malformed != 0 {
		t.Errorf("Files/Malformed = %d/%d, want 2/0", rep.Files, rep.Malformed)
	}
	if len(identities) != 1 {
		t.Fatalf("identities = %d, want 1 (dedup by id)", len(identities))
	}
	if identities[0].Runtime != "first" {
		t.Errorf("Runtime = %q, want %q (first file in sorted-path order wins)", identities[0].Runtime, "first")
	}
}
