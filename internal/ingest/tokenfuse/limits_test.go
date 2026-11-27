package tokenfuse

import (
	"strings"
	"testing"
)

// TestAStreamTooLongToReadIsNotCalledVerified: a line past the verifier's
// buffer means the chain was not checked through, and saying "intact" or
// "absent" there would be a claim nothing supports.
func TestAStreamTooLongToReadIsNotCalledVerified(t *testing.T) {
	long := `{"x":"` + strings.Repeat("a", 5<<20) + `"}` + "\n"
	c := verifyChain([]byte(long), "bus.ndjson")
	if c.Verified || c.Intact() {
		t.Errorf("chain over an unreadable stream = %+v, want not verified", c)
	}
}

func TestLoadRefusesAMalformedGlob(t *testing.T) {
	_, _, _, err := Load("bus/[.ndjson")
	if err == nil || !strings.Contains(err.Error(), "bad glob") {
		t.Errorf("Load(malformed glob) error = %v, want a bad-glob error", err)
	}
}
