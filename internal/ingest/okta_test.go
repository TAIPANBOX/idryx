package ingest

import "testing"

// TestOktaMalformedTimestampSkippedAndCounted is the regression test for a
// silently truncated Okta System Log: an entry whose "published" timestamp
// does not parse as RFC3339 was dropped with a bare `continue` and nothing
// anywhere said how many were skipped. For an identity plane, a silently
// truncated Okta log is a detection gap nobody can see. The good entries
// must still be ingested, and the drop must be counted.
func TestOktaMalformedTimestampSkippedAndCounted(t *testing.T) {
	data := []byte(`[
		{"published":"2026-05-29T10:00:00Z","eventType":"user.session.start",
		 "outcome":{"result":"SUCCESS"},"actor":{"alternateId":"alice@example.com"}},
		{"published":"not-a-timestamp","eventType":"user.session.start",
		 "outcome":{"result":"SUCCESS"},"actor":{"alternateId":"mallory@example.com"}},
		{"published":"2026-05-29T11:00:00Z","eventType":"user.session.start",
		 "outcome":{"result":"SUCCESS"},"actor":{"alternateId":"bob@example.com"}}
	]`)

	events, rep, err := Okta(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (the malformed-timestamp entry skipped)", len(events))
	}
	if rep.Records != 3 {
		t.Errorf("rep.Records = %d, want 3", rep.Records)
	}
	if rep.Malformed != 1 {
		t.Errorf("rep.Malformed = %d, want 1", rep.Malformed)
	}
	for _, e := range events {
		if e.IdentityID == "mallory@example.com" {
			t.Error("the malformed entry must not appear in the parsed events")
		}
	}
}

// TestOktaNoMalformedRecordsReportsZero pins the counterpart: a clean batch
// reports zero malformed, so a caller can distinguish "nothing was dropped"
// from "a drop was never counted in the first place".
func TestOktaNoMalformedRecordsReportsZero(t *testing.T) {
	data := []byte(`[
		{"published":"2026-05-29T10:00:00Z","eventType":"user.session.start",
		 "outcome":{"result":"SUCCESS"},"actor":{"alternateId":"alice@example.com"}}
	]`)
	events, rep, err := Okta(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || rep.Records != 1 || rep.Malformed != 0 {
		t.Errorf("events=%d rep=%+v, want 1 event, {Records:1 Malformed:0}", len(events), rep)
	}
}
