package sink

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// attr looks up a key's value in an OTLP attribute list, for readable
// assertions below instead of hunting through the slice by hand.
func attr(attrs []otlpKeyValue, key string) (string, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.StringValue, true
		}
	}
	return "", false
}

func TestOTLPSendsResourceSpansShape(t *testing.T) {
	var path, contentType string
	var received otlpPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("bad payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewOTLP(srv.URL, model.SeverityHigh).Send(sampleAlerts()); err != nil {
		t.Fatal(err)
	}

	if path != "/v1/traces" {
		t.Errorf("path = %q, want /v1/traces", path)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	if len(received.ResourceSpans) != 1 {
		t.Fatalf("resourceSpans = %d, want 1", len(received.ResourceSpans))
	}
	rs := received.ResourceSpans[0]
	if v, ok := attr(rs.Resource.Attributes, "service.name"); !ok || v != "idryx" {
		t.Errorf("resource service.name = %q, ok=%v, want idryx", v, ok)
	}

	if len(rs.ScopeSpans) != 1 {
		t.Fatalf("scopeSpans = %d, want 1", len(rs.ScopeSpans))
	}
	spans := rs.ScopeSpans[0].Spans
	// sampleAlerts() at SeverityHigh keeps impossible_travel (high) and
	// mfa_fatigue (critical), filtering out new_device (low); AtLeast
	// preserves order, so this is the expected span sequence.
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2 (severity filter should drop the low alert)", len(spans))
	}

	wantDetector := []string{"impossible_travel", "mfa_fatigue"}
	wantSeverity := []string{"high", "critical"}
	wantIdentity := []string{"a@x.com", "c@x.com"}
	wantSummary := []string{"far", "burst"}
	for i, span := range spans {
		if span.Name != wantDetector[i] {
			t.Errorf("span[%d].Name = %q, want %q", i, span.Name, wantDetector[i])
		}
		if span.Kind != 1 {
			t.Errorf("span[%d].Kind = %d, want 1 (SPAN_KIND_INTERNAL)", i, span.Kind)
		}
		if span.TraceID == "" || len(span.TraceID) != 32 {
			t.Errorf("span[%d].TraceID = %q, want 32 hex chars", i, span.TraceID)
		}
		if span.SpanID == "" || len(span.SpanID) != 16 {
			t.Errorf("span[%d].SpanID = %q, want 16 hex chars", i, span.SpanID)
		}
		if i > 0 && span.TraceID != spans[0].TraceID {
			t.Errorf("span[%d].TraceID = %q, want the batch's shared trace id %q", i, span.TraceID, spans[0].TraceID)
		}

		if v, ok := attr(span.Attributes, "idryx.detector"); !ok || v != wantDetector[i] {
			t.Errorf("span[%d] idryx.detector = %q, ok=%v, want %q", i, v, ok, wantDetector[i])
		}
		if v, ok := attr(span.Attributes, "idryx.severity"); !ok || v != wantSeverity[i] {
			t.Errorf("span[%d] idryx.severity = %q, ok=%v, want %q", i, v, ok, wantSeverity[i])
		}
		if v, ok := attr(span.Attributes, "idryx.identity"); !ok || v != wantIdentity[i] {
			t.Errorf("span[%d] idryx.identity = %q, ok=%v, want %q", i, v, ok, wantIdentity[i])
		}
		if v, ok := attr(span.Attributes, "idryx.summary"); !ok || v != wantSummary[i] {
			t.Errorf("span[%d] idryx.summary = %q, ok=%v, want %q", i, v, ok, wantSummary[i])
		}
	}
}

func TestOTLPSkipsEmptyBatch(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A batch that is entirely below the threshold must make no network
	// call at all, mirroring the Slack sink's own fully-filtered-batch case.
	lowOnly := []model.Alert{{Severity: model.SeverityLow, Detector: "x", IdentityID: "y"}}
	if err := NewOTLP(srv.URL, model.SeverityHigh).Send(lowOnly); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("expected no call for a fully filtered batch, got %d", calls)
	}
}

func TestOTLPErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := NewOTLP(srv.URL, model.SeverityNone).Send(sampleAlerts()); err == nil {
		t.Error("expected error on 500 status, got nil")
	}
}

func TestNewOTLPNormalizesEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     string
	}{
		{"http://localhost:4318", "http://localhost:4318/v1/traces"},
		{"http://localhost:4318/", "http://localhost:4318/v1/traces"},
		{"http://localhost:4318/v1/traces", "http://localhost:4318/v1/traces"},
		{"http://localhost:4318/v1/traces/", "http://localhost:4318/v1/traces"},
	}
	for _, c := range cases {
		got := NewOTLP(c.endpoint, model.SeverityHigh).url
		if got != c.want {
			t.Errorf("NewOTLP(%q).url = %q, want %q", c.endpoint, got, c.want)
		}
	}
}
