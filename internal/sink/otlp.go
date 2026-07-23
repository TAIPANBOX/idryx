package sink

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// OTLP posts alerts as OTLP/HTTP JSON trace spans, one span per alert, to an
// OTLP-compatible collector (Grafana Tempo, Datadog, Honeycomb, and similar
// all accept this wire format). It is hand-rolled directly against the
// OTLP/HTTP JSON envelope (resourceSpans -> scopeSpans -> spans ->
// attributes), the same approach Wardryx's own exporter uses
// (wardryx/internal/otel.go): no OpenTelemetry SDK dependency, just
// net/http and encoding/json.
type OTLP struct {
	url    string
	min    model.Severity
	client *http.Client
}

// NewOTLP returns an OTLP sink that sends alerts at or above min severity to
// endpoint's traces path. endpoint is normalized to end in "/v1/traces"
// (a trailing slash is trimmed first, and the suffix is not doubled if the
// caller already included it), matching wardryx's own exporter
// (wardryx/internal/otel.New) so the same collector URL works unchanged in
// either tool's config.
func NewOTLP(endpoint string, min model.Severity) *OTLP {
	base := strings.TrimRight(endpoint, "/")
	url := base
	if !strings.HasSuffix(base, "/v1/traces") {
		url = base + "/v1/traces"
	}
	return &OTLP{
		url:    url,
		min:    min,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OTLP) Name() string { return "otlp" }

// otlpPayload is the OTLP/HTTP JSON request body for POST .../v1/traces.
// Typed rather than map[string]any (contrast wardryx/internal/otel.go) to
// match this package's own payload idiom: see slackPayload and webhookAlert
// in the sibling sink files.
type otlpPayload struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue"`
}

func (o *OTLP) Send(alerts []model.Alert) error {
	alerts = AtLeast(alerts, o.min)
	if len(alerts) == 0 {
		return nil
	}

	// All alerts in one Send call came from one detect run, so they share
	// one trace id: the same per-run grouping wardryx's exporter gives one
	// agent run via its caller-supplied run_id, with idryx's own Sink
	// interface batching alerts per call instead of a run identifier.
	traceID := otlpTraceID(alerts)
	spans := make([]otlpSpan, 0, len(alerts))
	for _, a := range alerts {
		spans = append(spans, alertSpan(a, traceID))
	}

	payload := otlpPayload{
		ResourceSpans: []otlpResourceSpans{
			{
				Resource: otlpResource{
					Attributes: []otlpKeyValue{otlpAttr("service.name", "idryx")},
				},
				ScopeSpans: []otlpScopeSpans{
					{
						Scope: otlpScope{Name: "idryx"},
						Spans: spans,
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, o.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("otlp endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// alertSpan renders one alert as an OTLP span under the shared trace id.
// The span name is the detector, so distinct detectors read as distinct
// operations in a trace view. Attributes carry every field the Slack and
// webhook sinks already surface (see slack.go, webhook.go) so an operator
// sees the same alert content regardless of which sink delivered it; Alert's
// remaining field, Time, maps to the span's own start/end time rather than a
// duplicate attribute, the more idiomatic OTLP placement for a timestamp.
func alertSpan(a model.Alert, traceID string) otlpSpan {
	nanos := strconv.FormatInt(a.Time.UnixNano(), 10)
	return otlpSpan{
		TraceID: traceID,
		SpanID:  otlpSpanID(a),
		Name:    a.Detector,
		// SPAN_KIND_INTERNAL: an alert is idryx's own detection output, not
		// an inbound request it served or an outbound call it made (contrast
		// wardryx's SERVER span for its inbound /v1/decide).
		Kind:              1,
		StartTimeUnixNano: nanos,
		EndTimeUnixNano:   nanos,
		Attributes: []otlpKeyValue{
			otlpAttr("idryx.detector", a.Detector),
			otlpAttr("idryx.severity", a.Severity.String()),
			otlpAttr("idryx.identity", a.IdentityID),
			otlpAttr("idryx.summary", a.Summary),
		},
	}
}

func otlpAttr(key, value string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: value}}
}

// otlpTraceID derives a 16-byte OTLP trace id from every alert in the batch,
// so repeated calls with the same alerts (as in tests) are reproducible.
func otlpTraceID(alerts []model.Alert) string {
	h := sha256.New()
	fmt.Fprint(h, "idryx-trace")
	for _, a := range alerts {
		fmt.Fprintf(h, "|%s|%s|%s|%d|%s", a.Detector, a.IdentityID, a.Severity, a.Time.UnixNano(), a.Summary)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// otlpSpanID derives an 8-byte OTLP span id from one alert's own fields, so
// two distinct alerts in the same batch, even about the same identity at the
// same instant, do not collide on the same span id.
func otlpSpanID(a model.Alert) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("idryx-span|%s|%s|%s|%d|%s",
		a.Detector, a.IdentityID, a.Severity, a.Time.UnixNano(), a.Summary)))
	return hex.EncodeToString(sum[:8])
}
