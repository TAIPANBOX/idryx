package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// hostileID embeds the classic break-out payload for an onclick="f('<id>')"
// context: a single quote to close the JS string, then script. Identity IDs are
// taken verbatim from ingested inventory/IAM data, so this is attacker-reachable.
const hostileID = "agent:x');document.title='pwned';//"

func hostileServer() *Server {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{ID: hostileID, Type: model.IdentityAgent, Source: "agents"})
	g.AddEvent(model.Event{IdentityID: hostileID, Type: model.EventLogin, Outcome: "SUCCESS"})
	alerts := []model.Alert{{Detector: "shadow_ai", IdentityID: hostileID, Severity: model.SeverityHigh, Summary: "x"}}
	return New(g, alerts)
}

// servedDashboard returns the page a browser actually receives from `idryx
// serve`, with a hostile identity in the graph behind it.
func servedDashboard(t *testing.T) string {
	t.Helper()
	rr := httptest.NewRecorder()
	hostileServer().Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want %d", rr.Code, http.StatusOK)
	}
	return rr.Body.String()
}

// TestDashboardHTMLDoesNotEmbedIdentityData proves the dashboard is rendered
// client-side: the served HTML must not contain ingested identity IDs at all, so
// no server-side template injection is possible and escaping is governed by the
// client-side esc/escJS helpers.
//
// This property is necessary and NOT sufficient, which is why
// TestEventHandlerAttributesEscapeForJSContext exists beside it. This test
// passed unchanged for the whole time the identity list was building
// onclick="selectIdentity('<id>')" with the wrong escaper, because the wrong
// escaper is applied in the browser and never appears in this response.
func TestDashboardHTMLDoesNotEmbedIdentityData(t *testing.T) {
	if strings.Contains(servedDashboard(t), "document.title='pwned'") {
		t.Error("served dashboard HTML must not embed ingested identity IDs (would be server-side XSS)")
	}
}

// handlerAttr matches the opening of an HTML event-handler attribute
// (onclick=, onchange=, ...) inside the strings the dashboard's renderers
// concatenate. Everything from there to the closing quote is JavaScript
// source rather than HTML, and that is the whole point: the browser HTML-
// decodes an attribute value BEFORE handing it to the JS parser.
var handlerAttr = regexp.MustCompile(`\son[a-z]+="`)

// splice is the shape of an interpolation into one of those concatenated
// strings: the `' + ` that ends a literal chunk and opens an expression.
const splice = "' + "

// TestEventHandlerAttributesEscapeForJSContext holds the property that makes
// the dashboard safe, rather than a proxy for it: inside an HTML event-handler
// attribute, every interpolated value is escaped for the JAVASCRIPT context
// with escJS, never with esc.
//
// esc is an HTML-entity escaper: it turns ' into &#39;. In a handler attribute
// that is not a defence, it is the way out. The HTML parser decodes &#39; back
// into a real apostrophe before the JS parser sees the handler, so an ingested
// identity ID of
//
//	agent:x');document.title='pwned';//
//
// closes the string literal and runs on click. escJS hex-escapes every
// non-alphanumeric character, so nothing survives that can end a string or
// start a statement, and the value the handler receives is still the original
// ID (which is also what the lookups in selectIdentity and copyToClipboard
// need). SECURITY.md invariant 3 classes identity IDs from inventory and IAM
// data as attacker-influenced input.
//
// The check reads the page as served, so it covers every handler the dashboard
// ships, present and future, not only the three that exist today. It refuses a
// page in which it finds no interpolated handler at all: a check that goes
// green once its subject has vanished is worse than no check.
func TestEventHandlerAttributesEscapeForJSContext(t *testing.T) {
	page := servedDashboard(t)

	spliced := 0
	for _, loc := range handlerAttr.FindAllStringIndex(page, -1) {
		attr := strings.TrimSpace(page[loc[0]:loc[1]])
		rest := page[loc[1]:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			t.Fatalf("%s is never closed, so this check cannot read its body", attr)
		}
		body := rest[:end]

		// esc() inside a handler attribute is the defect: HTML escaping applied
		// to JavaScript source.
		if strings.Contains(body, "esc(") {
			t.Errorf("%s%s\" escapes an interpolated value with esc(), which emits &#39; for a quote;\n"+
				"the HTML parser decodes that back to ' before the JS parser reads the handler, so the\n"+
				"string literal can be closed from ingested data. Use escJS() in JS-string contexts.", attr, body)
		}

		// A raw interpolation, with no escaper at all, is the same hole without
		// the disguise. Anything spliced in here must go through escJS.
		for i := 0; ; {
			j := strings.Index(body[i:], splice)
			if j < 0 {
				break
			}
			i += j + len(splice)
			spliced++
			if !strings.HasPrefix(body[i:], "escJS(") {
				t.Errorf("%s%s\" interpolates %q without escJS(); every value spliced into a handler\n"+
					"attribute is JavaScript source and must be escaped for that context.",
					attr, body, firstToken(body[i:]))
			}
		}
	}

	if spliced == 0 {
		t.Fatal("found no interpolated event-handler attribute in the served dashboard.\n" +
			"Either the page stopped building handlers by concatenation (re-read this check against\n" +
			"the new shape) or it stopped serving them; either way this check is measuring nothing.")
	}
}

// firstToken returns enough of an interpolated expression to name it in a
// failure message.
func firstToken(s string) string {
	if i := strings.Index(s, " + "); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// TestAPIEncodesHostileIDSafely confirms the JSON the dashboard fetches encodes a
// quote-bearing identity ID as data, never as breakable markup. encoding/json
// guarantees this; the test is a regression guard against switching to a
// hand-rolled encoder.
func TestAPIEncodesHostileIDSafely(t *testing.T) {
	for _, path := range []string{"/api/identities", "/api/alerts"} {
		rr := httptest.NewRecorder()
		hostileServer().Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rr.Code)
		}
		// Body must be valid JSON (so the quote is encoded, not literal markup)...
		var v any
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
			t.Errorf("%s did not return valid JSON: %v", path, err)
		}
		// ...and must round-trip the exact hostile ID as a value.
		if !strings.Contains(rr.Body.String(), `agent:x');document.title=`) {
			t.Errorf("%s should carry the hostile ID as JSON data", path)
		}
	}
}
