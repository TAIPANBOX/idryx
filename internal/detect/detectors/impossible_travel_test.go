package detectors

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// Test coordinates: New York and London are ~5570 km apart.
const (
	nycLat, nycLon = 40.7128, -74.0060
	lonLat, lonLon = 51.5074, -0.1278
)

func geoLogin(id string, at time.Time, city string, lat, lon float64) model.Event {
	return model.Event{
		IdentityID: id,
		Type:       model.EventLogin,
		Outcome:    "SUCCESS",
		Time:       at,
		City:       city,
		Lat:        lat,
		Lon:        lon,
	}
}

func TestImpossibleTravel(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-24 * time.Hour)
	g := graph.New(map[string]bool{"admin@x.com": true})

	// bob: NYC -> London in 1h (~5570 km/h) -> high.
	g.AddEvent(geoLogin("bob@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(geoLogin("bob@x.com", base.Add(1*time.Hour), "London", lonLat, lonLon))

	// admin: same impossible hop, but privileged -> critical.
	g.AddEvent(geoLogin("admin@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(geoLogin("admin@x.com", base.Add(1*time.Hour), "London", lonLat, lonLon))

	// carol: NYC -> London in 10h (~557 km/h) is a normal flight; no alert.
	g.AddEvent(geoLogin("carol@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(geoLogin("carol@x.com", base.Add(10*time.Hour), "London", lonLat, lonLon))

	got := detect(NewImpossibleTravel(), g)

	if a, ok := got["bob@x.com"]; !ok {
		t.Error("expected bob's NYC->London 1h hop to be flagged")
	} else if a.Severity != model.SeverityHigh {
		t.Errorf("bob severity = %v, want high", a.Severity)
	}

	if a, ok := got["admin@x.com"]; !ok {
		t.Error("expected privileged admin's impossible hop to be flagged")
	} else if a.Severity != model.SeverityCritical {
		t.Errorf("admin severity = %v, want critical (privileged)", a.Severity)
	}

	if _, ok := got["carol@x.com"]; ok {
		t.Error("carol's NYC->London in 10h is feasible; should not alert")
	}
}

func TestImpossibleTravelEdgeCases(t *testing.T) {
	withFixedNow(t)
	base := fixedNow().Add(-24 * time.Hour)
	g := graph.New(nil)

	// dave: two far-apart logins at the exact same instant — zero time delta
	// must be skipped, not treated as infinite speed.
	g.AddEvent(geoLogin("dave@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(geoLogin("dave@x.com", base, "London", lonLat, lonLon))

	// erin: repeated logins from the same location — zero distance.
	g.AddEvent(geoLogin("erin@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(geoLogin("erin@x.com", base.Add(1*time.Minute), "New York", nycLat, nycLon))

	// frank: the London event has no geo data, so it cannot pair with NYC.
	g.AddEvent(geoLogin("frank@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(model.Event{
		IdentityID: "frank@x.com", Type: model.EventLogin, Outcome: "SUCCESS",
		Time: base.Add(1 * time.Hour), City: "London",
	})

	// gwen: the impossible second hop is a FAILED login; only successes count.
	g.AddEvent(geoLogin("gwen@x.com", base, "New York", nycLat, nycLon))
	g.AddEvent(model.Event{
		IdentityID: "gwen@x.com", Type: model.EventLogin, Outcome: "FAILURE",
		Time: base.Add(1 * time.Hour), City: "London", Lat: lonLat, Lon: lonLon,
	})

	if got := detect(NewImpossibleTravel(), g); len(got) != 0 {
		t.Errorf("expected no alerts for edge cases, got %v", got)
	}
}
