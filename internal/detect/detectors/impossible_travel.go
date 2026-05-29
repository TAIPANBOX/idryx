// Package detectors holds the concrete ITDR detectors.
package detectors

import (
	"fmt"
	"math"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// maxFeasibleKmh is the sustained speed above which travel between two logins is
// physically impossible (well above commercial aviation).
const maxFeasibleKmh = 1000

// ImpossibleTravel flags two successful logins for one identity that are too far
// apart to be reached in the elapsed time.
type ImpossibleTravel struct{}

func NewImpossibleTravel() *ImpossibleTravel { return &ImpossibleTravel{} }

func (d *ImpossibleTravel) Name() string { return "impossible_travel" }

func (d *ImpossibleTravel) Detect(g *graph.Store) []model.Alert {
	var alerts []model.Alert
	for _, id := range g.Identities() {
		var prev *model.Event
		for i := range id.Events {
			e := &id.Events[i]
			if e.Type != model.EventLogin || e.Outcome != "SUCCESS" {
				continue
			}
			if !hasGeo(e) {
				continue
			}
			if prev != nil {
				hours := e.Time.Sub(prev.Time).Hours()
				if hours > 0 {
					km := haversineKm(prev.Lat, prev.Lon, e.Lat, e.Lon)
					if km/hours > maxFeasibleKmh {
						sev := model.SeverityHigh
						if id.Privileged {
							sev = model.SeverityCritical
						}
						alerts = append(alerts, model.Alert{
							Detector:   d.Name(),
							IdentityID: id.ID,
							Severity:   sev,
							Time:       e.Time,
							Summary: fmt.Sprintf("%.0f km in %.1fh (%.0f km/h) between %s and %s",
								km, hours, km/hours, prev.City, e.City),
						})
					}
				}
			}
			prev = e
		}
	}
	return alerts
}

func hasGeo(e *model.Event) bool {
	return e.Lat != 0 || e.Lon != 0
}

// haversineKm returns the great-circle distance between two points in km.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthKm = 6371.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := rad(lat2 - lat1)
	dLon := rad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthKm * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
