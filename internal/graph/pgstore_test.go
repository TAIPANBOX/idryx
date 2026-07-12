package graph

import (
	"strings"
	"testing"
)

// TestEventsSnapshotOrderHasIDTiebreaker is the regression test for the
// Store/PgStore ordering parity gap: Snapshot's events query ordered only by
// (identity_id, ts). Postgres gives no defined order for rows with equal ts
// beyond that, while in-memory Store.Identities uses sort.SliceStable, which
// preserves append (insertion) order for equal timestamps. Two events with
// identical ts could therefore order differently across backends, flipping
// which one new_device/impossible_travel treats as baseline vs anomaly. This
// is a plain unit test (no live Postgres needed) so it runs in the standard
// `go test ./...` gate; a live-DB counterpart lives in
// pgstore_integration_test.go.
func TestEventsSnapshotOrderHasIDTiebreaker(t *testing.T) {
	const want = "ORDER BY identity_id, ts, id"
	if !strings.Contains(eventsOrderBy, want) {
		t.Errorf("eventsOrderBy = %q, want it to contain %q so equal-ts events order deterministically (matching in-memory Store's insertion-order tiebreak)", eventsOrderBy, want)
	}
}
