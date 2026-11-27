package aiusage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDisagreementNamesEveryShape walks every combination of the three sides,
// so no shape can quietly fall through to the generic wording.
func TestDisagreementNamesEveryShape(t *testing.T) {
	d, o, c := []string{"agent:a"}, []string{"agent:a"}, 3
	cases := []struct {
		row  Row
		want string
	}{
		{Row{DeclaredBy: d, ObservedBy: o, CodeSites: c}, ""},
		{Row{ObservedBy: o}, "reached, and declared by nobody"},
		{Row{ObservedBy: o, CodeSites: c}, "reached, and declared by nobody"},
		{Row{DeclaredBy: d}, "declared, and neither reached nor in code"},
		{Row{DeclaredBy: d, CodeSites: c}, "declared and in code, not observed reaching it"},
		{Row{CodeSites: c}, "in code, declared by nobody"},
		{Row{DeclaredBy: d, ObservedBy: o}, "not in every source"},
	}
	for _, tc := range cases {
		if got := disagreement(tc.row); got != tc.want {
			t.Errorf("disagreement(declared=%v observed=%v coded=%v) = %q, want %q",
				tc.row.Declared(), tc.row.Observed(), tc.row.Coded(), got, tc.want)
		}
	}
}

// TestHumanSaysSoWhenNoSourceNamesAProvider: an empty table is a sentence,
// never a header over nothing.
func TestHumanSaysSoWhenNoSourceNamesAProvider(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, Report{})
	out := buf.String()
	if !strings.Contains(out, "No provider is named by any of the three sources.") {
		t.Errorf("empty report did not say so:\n%s", out)
	}
	if strings.Contains(out, "PROVIDER\t") || strings.Contains(out, "SOURCE  ") || strings.Contains(out, "By agent or service") {
		t.Errorf("empty sections printed headers:\n%s", out)
	}
}

// TestEscapeWritesInvalidBytesAsHex: bytes that are not UTF-8 reach the
// terminal as \xNN, never raw.
func TestEscapeWritesInvalidBytesAsHex(t *testing.T) {
	got := escape("ok\xff\xfe", 64)
	if got != `ok\xff\xfe` {
		t.Errorf("escape = %q, want ok\\xff\\xfe", got)
	}
}

func TestLoadCodeScanReadsAFileAndRefusesAMissingOne(t *testing.T) {
	if _, err := LoadCodeScan(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing code scan was read")
	}
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodeScan(path); err == nil {
		t.Error("a file that is not a code scan was accepted")
	}
}
