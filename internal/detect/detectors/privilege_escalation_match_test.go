package detectors

import (
	"strings"
	"testing"
)

// matchDangerousAction was at 0%. A detector predicate that stops matching does
// not error: the detector runs, finds nothing, and an estate with a live
// escalation path reads as an estate with none. A detector predicate that
// matches too much is the mirror, and worse in practice, because the real
// findings drown.
//
// Both directions are pinned here, and the doc comment on the function is the
// specification each case comes from.

func TestABareWildcardIsDeliberatelyNotAnEscalationFinding(t *testing.T) {
	t.Parallel()

	// "*" is a grant of EVERYTHING, which the connector already flags as
	// admin-equivalent and over_privileged_nhi already reports. This detector
	// is for the stealthy path: an identity that is not admin and can become
	// one. An identity holding every action is neither stealthy nor something
	// this detector adds to.
	//
	// "Fixing" this to match would fire on every admin identity in an estate
	// and bury the escalation paths this detector exists to surface.
	if _, ok := matchDangerousAction("*"); ok {
		t.Error("a bare * must not be an escalation finding: it is already reported " +
			"as admin-equivalent, and matching it here buries the stealthy paths " +
			"this detector is for")
	}
}

func TestAWildcardGrantNamesThePermissionsItCoversRatherThanEchoingTheWildcard(t *testing.T) {
	t.Parallel()

	// A reader given "iam:*" has to go and look up what that holds. A reader
	// given the names does not, and the names are sorted so the same graph
	// produces the same text rather than a different one per run.
	desc, ok := matchDangerousAction("iam:*")
	if !ok {
		t.Fatal("iam:* must match: it holds every IAM escalation permission there is")
	}
	if strings.Contains(desc, "iam:*") {
		t.Errorf("the summary echoes the wildcard instead of naming what it covers: %s", desc)
	}
	if !strings.Contains(desc, "iam:") {
		t.Errorf("the summary names no permission at all: %s", desc)
	}

	// Twice, same answer. The key list is built from a map and sorted exactly
	// so this holds; without the sort the text would differ per run and a
	// reader comparing two reports would see a change that is not one.
	again, _ := matchDangerousAction("iam:*")
	if again != desc {
		t.Errorf("the same wildcard produced two different summaries:\n  %s\n  %s", desc, again)
	}
}

func TestALargeWildcardIsTruncatedAndSaysHowManyItLeftOut(t *testing.T) {
	t.Parallel()

	// The cap exists so a summary stays readable. Truncating silently would
	// understate the grant, so the count of what was left out is part of it.
	desc, ok := matchDangerousAction("iam:*")
	if !ok {
		t.Fatal("iam:* must match")
	}
	if !strings.Contains(desc, "more") {
		t.Errorf("a wildcard covering more than the cap must say how many it left "+
			"out, or the summary understates the grant: %s", desc)
	}
	// The total is stated regardless of how many are named.
	if !strings.Contains(desc, "permission") {
		t.Errorf("the summary must say how many permissions the grant covers: %s", desc)
	}
}

func TestAWildcardMatchingNothingIsNotAFinding(t *testing.T) {
	t.Parallel()

	// A prefix nobody dangerous starts with must not produce a finding with an
	// empty permission list, which would read as an escalation covering zero
	// permissions.
	for _, harmless := range []string{"s3:getobj*", "logs:*", "zzz*"} {
		if desc, ok := matchDangerousAction(harmless); ok {
			t.Errorf("%q matched nothing dangerous yet produced a finding: %s", harmless, desc)
		}
	}
}

func TestAnExactPermissionStillMatchesThroughTheWildcardPath(t *testing.T) {
	t.Parallel()

	// A non-wildcard action falls through to the exact matcher, so the wildcard
	// branch must not have swallowed the ordinary case.
	if _, ok := matchDangerousAction("iam:passrole"); !ok {
		t.Error("an exact dangerous permission must still be found")
	}
	// And the bounded-match rule still holds: a longer identifier that merely
	// starts with a dangerous name is not one.
	if _, ok := matchDangerousAction("iam:passrolespecial"); ok {
		t.Error("iam:passrolespecial is a different permission and must not match " +
			"iam:passrole")
	}
}
