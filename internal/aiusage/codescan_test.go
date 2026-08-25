package aiusage

import (
	"strings"
	"testing"
)

const realDocument = `{
  "schema": "qryx.ai-inventory/v1",
  "tool": { "name": "qryx", "version": "v0.4.0" },
  "generatedAt": "2026-08-25T18:08:22Z",
  "root": "/src",
  "filesWalked": 63,
  "entries": [
    { "provider": "anthropic", "role": "provider", "label": "Anthropic SDK (python)",
      "occurrences": [ { "file": "a.py", "line": 2 }, { "file": "requirements.txt", "line": 1 } ] },
    { "provider": "openai", "role": "provider", "label": "OpenAI API endpoint",
      "occurrences": [ { "file": "cfg.yaml", "line": 5 } ] },
    { "provider": "", "role": "framework", "label": "LangChain (python)",
      "occurrences": [ { "file": "chain.py", "line": 19 }, { "file": "b.py", "line": 3 } ] }
  ],
  "limits": [ "An empty result is not proof that a tree uses no AI." ]
}`

func TestParseCodeScanReadsTheRealDocument(t *testing.T) {
	scan, err := ParseCodeScan([]byte(realDocument))
	if err != nil {
		t.Fatalf("ParseCodeScan: %v", err)
	}
	if scan.Root != "/src" || !strings.Contains(scan.Tool, "qryx") {
		t.Errorf("root = %q, tool = %q", scan.Root, scan.Tool)
	}
	if got := scan.Providers["anthropic"].Sites; got != 2 {
		t.Errorf("anthropic sites = %d, want 2 (one per occurrence, not one per row)", got)
	}
	if got := scan.Providers["openai"].Sites; got != 1 {
		t.Errorf("openai sites = %d, want 1", got)
	}
	if got := scan.SortedProviders(); len(got) != 2 || got[0] != "anthropic" || got[1] != "openai" {
		t.Errorf("providers = %v, want [anthropic openai]", got)
	}
}

// TestParseCodeScanRefusesAnotherSchema is the one refusal that matters here.
// The coded leg has no subject and no second opinion, so a reader that quietly
// accepted a shape it does not know would report an empty code column, and an
// empty code column is indistinguishable from an estate whose code reaches no
// model at all.
func TestParseCodeScanRefusesAnotherSchema(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"a later version", `{"schema":"qryx.ai-inventory/v2","entries":[]}`},
		{"a different document", `{"schema":"CycloneDX","entries":[]}`},
		{"no schema at all", `{"entries":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCodeScan([]byte(tc.doc)); err == nil {
				t.Fatal("accepted a document this reader does not know, which would read as an empty code column")
			}
		})
	}
}

// TestFrameworkRowsBecomeALimitRatherThanARow holds the honest handling of the
// case qryx deliberately reports with no provider: the tree reaches a model
// through LangChain or LiteLLM and which one is chosen by configuration a text
// scan cannot read.
//
// It cannot appear in a per-provider table, because there is no provider. It
// must not be dropped in silence either, because then a reader concludes the
// code reaches only the providers listed. So it becomes a limit, with its
// counts.
func TestFrameworkRowsBecomeALimitRatherThanARow(t *testing.T) {
	scan, err := ParseCodeScan([]byte(realDocument))
	if err != nil {
		t.Fatalf("ParseCodeScan: %v", err)
	}
	if _, ok := scan.Providers[""]; ok {
		t.Error("an empty provider became a row")
	}
	joined := strings.Join(scan.Limits, " ")
	if !strings.Contains(joined, "indirection") {
		t.Fatalf("the framework row vanished without a word: %q", joined)
	}
	if !strings.Contains(joined, "1 row(s) at 2 site(s)") {
		t.Errorf("the limit does not carry the counts: %q", joined)
	}
}

// TestParseCodeScanRejectsGarbage: a truncated or non-JSON file must be an
// error rather than an empty scan, for the same reason as the schema check.
func TestParseCodeScanRejectsGarbage(t *testing.T) {
	if _, err := ParseCodeScan([]byte(`{"schema": "qryx.ai-inv`)); err == nil {
		t.Fatal("accepted truncated JSON")
	}
}

// TestCodeScanProviderIsLowercased: the document is written by another tool,
// and SPEC 4.7 obliges a consumer to lowercase before comparing. Doing it at
// the door means the reconciliation never sees two spellings of one provider.
func TestCodeScanProviderIsLowercased(t *testing.T) {
	doc := `{"schema":"qryx.ai-inventory/v1","entries":[
	  {"provider":"Anthropic","label":"x","occurrences":[{"file":"a","line":1}]}]}`
	scan, err := ParseCodeScan([]byte(doc))
	if err != nil {
		t.Fatalf("ParseCodeScan: %v", err)
	}
	if _, ok := scan.Providers["anthropic"]; !ok {
		t.Errorf("providers = %v, want a lowercased anthropic", scan.SortedProviders())
	}
}
