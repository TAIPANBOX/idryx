package stream

import (
	"reflect"
	"strings"
	"testing"
)

// By convention a stream named <source>.ndjson carries <source>, for every
// source the registry knows.
func TestEveryKnownSourceMayCarryItsOwnStream(t *testing.T) {
	p := Default()
	for _, s := range knownSources {
		if got := p.Check(s, s); got != Allowed {
			t.Errorf("%s.ndjson carrying %s: %v, want Allowed", s, s, got)
		}
	}
}

// The case the rule exists for: another plane's name inside a file that is not
// that plane's.
func TestAKnownStreamRefusesAnotherSourcesName(t *testing.T) {
	p := Default()
	if got := p.Check("tokenfuse", "wardryx"); got != Foreign {
		t.Fatalf("wardryx inside tokenfuse.ndjson: %v, want Foreign", got)
	}
	if got := p.Check("wardryx", "tokenfuse"); got != Foreign {
		t.Fatalf("tokenfuse inside wardryx.ndjson: %v, want Foreign", got)
	}
	// Exact match only: no case folding, no whitespace trimming, no prefix.
	for _, claim := range []string{"Tokenfuse", " tokenfuse", "tokenfuse ", "tokenfuse-cloud", "", "tokenfus"} {
		if got := p.Check("tokenfuse", claim); got != Foreign {
			t.Errorf("claim %q inside tokenfuse.ndjson: %v, want Foreign", claim, got)
		}
	}
}

// The measured exceptions, each by the row that was read from the producers
// and the launchers.
func TestTheMeasuredExceptionsAreDeclared(t *testing.T) {
	p := Default()
	for _, stem := range []string{"tokenfuse-cloud", "tokenfuse-mcp"} {
		if got := p.Check(stem, "tokenfuse"); got != Allowed {
			t.Errorf("%s.ndjson carrying tokenfuse: %v, want Allowed", stem, got)
		}
		if got := p.Check(stem, "wardryx"); got != Foreign {
			t.Errorf("%s.ndjson carrying wardryx: %v, want Foreign", stem, got)
		}
	}
}

// demo.ndjson is NOT a built-in exception: the events directory is writable by
// co-tenants, so a built-in multi-source file is a file any of them can create
// to speak as any plane. It is an unknown stream until an operator declares it.
func TestDemoIsNotInTheDefaultTableAndIsOptIn(t *testing.T) {
	p := Default()
	for _, source := range []string{"tokenfuse", "wardryx", "engram", "qryx", "verdryx", "mockryx"} {
		if got := p.Check("demo", source); got != Foreign {
			t.Errorf("an undeclared demo.ndjson carrying %s: %v, want Foreign", source, got)
		}
	}
	if got := p.Check("demo", "demo"); got != AllowedUnknownStem {
		t.Errorf("an undeclared demo.ndjson carrying demo: %v, want AllowedUnknownStem", got)
	}
	extra, err := ParseExtra("demo=tokenfuse|wardryx|engram|qryx|verdryx|mockryx")
	if err != nil {
		t.Fatal(err)
	}
	declared := p.Extend(extra)
	for _, source := range []string{"tokenfuse", "wardryx", "engram", "qryx", "verdryx", "mockryx"} {
		if got := declared.Check("demo", source); got != Allowed {
			t.Errorf("a declared demo.ndjson carrying %s: %v, want Allowed", source, got)
		}
	}
}

// agent-conform (agent-stack-go#66, registered in agent-passport#69) writes
// agent-conform.ndjson with source agent-conform: a known single-source stream,
// not an unknown one.
func TestAgentConformIsAKnownSingleSourceStream(t *testing.T) {
	p := Default()
	if got := p.Check("agent-conform", "agent-conform"); got != Allowed {
		t.Fatalf("agent-conform.ndjson carrying agent-conform: %v, want Allowed", got)
	}
	if got := p.Check("agent-conform", "tokenfuse"); got != Foreign {
		t.Fatalf("agent-conform.ndjson carrying tokenfuse: %v, want Foreign", got)
	}
	if got := p.Check("tokenfuse", "agent-conform"); got != Foreign {
		t.Fatalf("tokenfuse.ndjson carrying agent-conform: %v, want Foreign", got)
	}
}

// A table that names a source the registry does not know has drifted from the
// registry it was read from.
func TestEveryExceptionNamesOnlySourcesTheRegistryKnows(t *testing.T) {
	known := map[string]bool{}
	for _, s := range knownSources {
		known[s] = true
	}
	for stem, sources := range exceptions {
		for _, s := range sources {
			if !known[s] {
				t.Errorf("exception %s lists %s, which is not a registered source", stem, s)
			}
		}
	}
}

// An undeclared stem is not trusted in silence and not dropped: its own name is
// accepted and marked, anything else is the forgery case.
func TestAnUndeclaredStemIsMarkedNotTrusted(t *testing.T) {
	p := Default()
	if got := p.Check("newplane", "newplane"); got != AllowedUnknownStem {
		t.Fatalf("an undeclared stem carrying its own name: %v, want AllowedUnknownStem", got)
	}
	if got := p.Check("newplane", "tokenfuse"); got != Foreign {
		t.Fatalf("an undeclared stem carrying tokenfuse: %v, want Foreign", got)
	}
	if got := p.Check("events", "tokenfuse"); got != Foreign {
		t.Fatalf("events.ndjson carrying tokenfuse: %v, want Foreign", got)
	}
}

// The operator's declaration widens what a stem may carry and never narrows
// what the table already knows.
func TestADeclarationWidensAndNeverNarrows(t *testing.T) {
	extra, err := ParseExtra("events=tokenfuse|wardryx, tokenfuse=wardryx")
	if err != nil {
		t.Fatal(err)
	}
	p := Default().Extend(extra)
	if got := p.Check("events", "wardryx"); got != Allowed {
		t.Errorf("a declared stem: %v, want Allowed", got)
	}
	if got := p.Check("events", "engram"); got != Foreign {
		t.Errorf("a declared stem carrying an undeclared source: %v, want Foreign", got)
	}
	if got := p.Check("tokenfuse", "wardryx"); got != Allowed {
		t.Errorf("a widened known stem: %v, want Allowed", got)
	}
	if got := p.Check("tokenfuse", "tokenfuse"); got != Allowed {
		t.Errorf("the built-in row survived the declaration: %v, want Allowed", got)
	}
	// Extend copies: the default policy is untouched.
	if got := Default().Check("tokenfuse", "wardryx"); got != Foreign {
		t.Errorf("Extend leaked into the default policy: %v", got)
	}
}

func TestAllowedForNamesWhatWouldHaveBeenAccepted(t *testing.T) {
	p := Default()
	if got, want := p.AllowedFor("tokenfuse"), []string{"tokenfuse"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tokenfuse: %v, want %v", got, want)
	}
	if got, want := p.AllowedFor("agent-conform"), []string{"agent-conform"}; !reflect.DeepEqual(got, want) {
		t.Errorf("agent-conform: %v, want %v", got, want)
	}
	if got, want := p.AllowedFor("newplane"), []string{"newplane"}; !reflect.DeepEqual(got, want) {
		t.Errorf("an undeclared stem: %v, want %v", got, want)
	}
}

func TestStem(t *testing.T) {
	for in, want := range map[string]string{
		"/var/lib/stack/events/tokenfuse.ndjson":     "tokenfuse",
		"/var/lib/stack/events/tokenfuse-mcp.ndjson": "tokenfuse-mcp",
		"relative/wardryx.ndjson":                    "wardryx",
		"/x/events.jsonl":                            "events",
		"/x/noext":                                   "noext",
		"/x/a.b.ndjson":                              "a.b",
	} {
		if got := Stem(in); got != want {
			t.Errorf("Stem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseExtra(t *testing.T) {
	got, err := ParseExtra(" events=tokenfuse|wardryx , mix=a|b ,, events=engram ")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"events": {"tokenfuse", "wardryx", "engram"}, "mix": {"a", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := ParseExtra("   "); got != nil || err != nil {
		t.Fatalf("an empty declaration is no declaration: %v, %v", got, err)
	}
}

// A malformed entry is an error that names it. The rule fails closed, so an
// entry silently ignored would read as a producer that stopped being heard.
func TestAMalformedDeclarationIsAnErrorNotASkip(t *testing.T) {
	for _, bad := range []string{
		"events",                            // no source list
		"events=",                           // empty source
		"=tokenfuse",                        // no stem
		"events=tokenfuse|",                 // empty alternative
		"a b=tokenfuse",                     // space in stem
		"events=token fuse",                 // space in source
		"events=a\nBcc: x",                  // control characters
		"../x=tokenfuse",                    // path separator
		"events=" + strings.Repeat("a", 65), // too long
	} {
		if _, err := ParseExtra(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestValidNameIsWhatADeclarationCanCarry(t *testing.T) {
	for _, ok := range []string{"tokenfuse", "tokenfuse-cloud", "a.b", "Events", "x1"} {
		if !ValidName(ok) {
			t.Errorf("%q should be a valid name", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a\nb", "wardryx\r\nBcc: x", "../x", "a|b", "a=b", strings.Repeat("a", 65), "-lead"} {
		if ValidName(bad) {
			t.Errorf("%q must not be a valid name", bad)
		}
	}
}
