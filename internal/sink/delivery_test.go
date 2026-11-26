package sink

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// allSinks builds the three HTTP sinks against url with no severity filter.
func allSinks(url string) []Sink {
	return []Sink{
		NewSlack(url, model.SeverityNone),
		NewWebhook(url, model.SeverityNone, nil),
		NewOTLP(url, model.SeverityNone),
	}
}

// TestEverySinkNamesItselfDistinctly: the CLI prints "sink <name>: <err>"
// for a failed delivery, so an operator can only tell which destination
// failed if the names differ.
func TestEverySinkNamesItselfDistinctly(t *testing.T) {
	want := []string{"slack", "webhook", "otlp"}
	for i, s := range allSinks("http://127.0.0.1:1") {
		if s.Name() != want[i] {
			t.Errorf("sink %d named %q, want %q", i, s.Name(), want[i])
		}
	}
}

// TestEverySinkTreatsOnly2xxAsDelivered sweeps the status boundary: 299 is
// delivered, 300 and above are not (a redirect is not a delivery; the
// client does not follow one without a Location).
func TestEverySinkTreatsOnly2xxAsDelivered(t *testing.T) {
	for _, code := range []int{200, 202, 299, 300, 302, 400, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		for _, s := range allSinks(srv.URL) {
			err := s.Send(sampleAlerts())
			if code < 300 && err != nil {
				t.Errorf("%s: status %d reported as a failure: %v", s.Name(), code, err)
			}
			if code >= 300 {
				if err == nil {
					t.Errorf("%s: status %d reported as delivered", s.Name(), code)
				} else if !strings.Contains(err.Error(), "returned ") {
					t.Errorf("%s: status %d error %q does not name the status", s.Name(), code, err)
				}
			}
		}
		srv.Close()
	}
}

// TestEverySinkReportsADestinationThatIsNotThere: a closed port and a URL
// that cannot form a request are both failures, never a silent success.
func TestEverySinkReportsADestinationThatIsNotThere(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	closed := srv.URL
	srv.Close()

	for _, url := range []string{closed, "http://[::1"} {
		for _, s := range allSinks(url) {
			if err := s.Send(sampleAlerts()); err == nil {
				t.Errorf("%s: delivery to %q reported success", s.Name(), url)
			}
		}
	}
}

// TestEverySinkSendsNothingBelowItsThreshold: a batch filtered to empty
// makes no request at all, so even an unreachable destination is not an error.
func TestEverySinkSendsNothingBelowItsThreshold(t *testing.T) {
	low := []model.Alert{{Detector: "new_device", IdentityID: "a@x.com", Severity: model.SeverityLow}}
	for _, s := range []Sink{
		NewSlack("http://127.0.0.1:1", model.SeverityHigh),
		NewWebhook("http://127.0.0.1:1", model.SeverityHigh, nil),
		NewOTLP("http://127.0.0.1:1", model.SeverityHigh),
	} {
		if err := s.Send(low); err != nil {
			t.Errorf("%s: a filtered-out batch still tried to deliver: %v", s.Name(), err)
		}
	}
}
