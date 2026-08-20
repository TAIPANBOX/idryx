package baseline

import (
	"strings"
	"testing"
)

// RareCountries was at 0%. It is what explains WHY an event scored high, which
// is the sentence an analyst reads before deciding whether a login was the
// person or somebody else.

func profileWith(counts map[string]int) *Profile {
	p := &Profile{IdentityID: "agent://acme/bot", Countries: map[string]int{}}
	for c, n := range counts {
		p.Countries[c] = n
		p.TotalLogins += n
	}
	return p
}

func TestOnlyCountriesAtOrBelowTheThresholdAreCalledRare(t *testing.T) {
	t.Parallel()

	p := profileWith(map[string]int{"UA": 400, "PL": 12, "SG": 2, "BR": 1})

	got := p.RareCountries(2)
	if len(got) != 2 {
		t.Fatalf("got %v, want the two countries seen at most twice", got)
	}
	for _, c := range got {
		if p.Countries[c] > 2 {
			t.Errorf("%s was seen %d times and is not rare", c, p.Countries[c])
		}
	}
	for _, common := range []string{"UA", "PL"} {
		if strings.Contains(strings.Join(got, ","), common) {
			t.Errorf("%s is the identity's ordinary place and must not be called rare: %v", common, got)
		}
	}
}

func TestTheSameProfileAlwaysExplainsItselfTheSameWay(t *testing.T) {
	t.Parallel()

	// Go randomizes map iteration. Without the sort, the same profile would
	// produce a different explanation on every run, and an analyst comparing
	// two reports of the same identity would see a change that is not one.
	p := profileWith(map[string]int{
		"BR": 1, "SG": 1, "NG": 1, "VN": 2, "KZ": 2, "MD": 1,
	})

	first := strings.Join(p.RareCountries(2), ",")
	for i := 0; i < 50; i++ {
		if got := strings.Join(p.RareCountries(2), ","); got != first {
			t.Fatalf("run %d gave %q, the first gave %q; the order comes from a map "+
				"and must be sorted before it reaches a reader", i, got, first)
		}
	}
}

func TestTheRarestComeFirstAndTiesAreBrokenByName(t *testing.T) {
	t.Parallel()

	// Rarest first, because that is the order an analyst reads: the single
	// login from somewhere new is the one worth looking at, not the one seen
	// twice.
	p := profileWith(map[string]int{"ZZ": 1, "AA": 2, "BB": 1})

	got := p.RareCountries(2)
	if len(got) != 3 {
		t.Fatalf("got %v, want all three", got)
	}
	if p.Countries[got[0]] > p.Countries[got[len(got)-1]] {
		t.Errorf("the rarest must come first, got %v", got)
	}
	// BB and ZZ are both seen once; the tie is broken by name so the text is
	// stable rather than merely deterministic-looking.
	if got[0] != "BB" || got[1] != "ZZ" {
		t.Errorf("a tie must be broken by name, got %v", got)
	}
}

func TestAProfileWithNothingRareExplainsNothingRatherThanEverything(t *testing.T) {
	t.Parallel()

	// The empty answer matters: a profile whose every country is well
	// established has no rare-country explanation, and returning them all
	// would attach a reason to a score that did not come from one.
	p := profileWith(map[string]int{"UA": 400, "PL": 120})
	if got := p.RareCountries(2); len(got) != 0 {
		t.Errorf("got %v, want nothing: none of these is rare", got)
	}

	empty := &Profile{IdentityID: "agent://acme/new", Countries: map[string]int{}}
	if got := empty.RareCountries(2); len(got) != 0 {
		t.Errorf("a profile with no logins at all must explain nothing, got %v", got)
	}
}
