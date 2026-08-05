package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestEgress(t *testing.T) {
	data := []byte(`{
	  "flows": [
	    {"time":"2026-05-29T10:00:00Z","identity":"arn:role/etl","destination":"api.openai.com:443","bytes":1024},
	    {"time":"2026-05-29T10:05:00Z","identity":"arn:role/etl","destination":"s3.amazonaws.com:443","bytes":2048},
	    {"time":"bad-timestamp","identity":"skip","destination":"x","bytes":0}
	  ]
	}`)

	events, rep, err := Egress(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (invalid timestamp skipped)", len(events))
	}
	if events[0].Type != model.EventEgress {
		t.Errorf("event type = %q, want egress", events[0].Type)
	}
	if events[0].Resource != "api.openai.com:443" {
		t.Errorf("resource = %q", events[0].Resource)
	}
	if events[0].IdentityID != "arn:role/etl" || events[0].Outcome != "SUCCESS" {
		t.Errorf("event0 = %+v", events[0])
	}
	// The malformed "bad-timestamp" flow above must be counted, not just
	// silently skipped: a silently truncated egress log is a detection gap
	// nobody can see.
	if rep.Records != 3 {
		t.Errorf("rep.Records = %d, want 3", rep.Records)
	}
	if rep.Malformed != 1 {
		t.Errorf("rep.Malformed = %d, want 1", rep.Malformed)
	}
}
