package detectors

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// Beaconing flags an identity whose outbound connections to one destination
// arrive on a regular cadence: the shape of a process checking in with
// something on a timer, rather than of one doing work.
//
// **What makes this worth detecting.** A human-driven workload connects when
// there is something to do, so its intervals are irregular by nature. Automated
// check-in is the opposite: a fixed period, usually with small jitter to look
// less obvious. That regularity is the signal, and it is visible without
// reading a single byte of what was sent, which is why it fits a sensor that
// promises never to look inside a payload (SECURITY.md).
//
// **It is not an accusation and the summary says so.** Cron, a metrics agent, a
// package-manager check and a health probe all beacon perfectly. The finding is
// "this identity has a heartbeat to this destination", and it is worth an
// operator's minute because a heartbeat from something they cannot name is a
// different thing from a heartbeat from something they installed. Severity
// stays medium for that reason, and rises when the destination is a known LLM
// API, where a fixed cadence is a poll rather than a conversation.
//
// # Why the coefficient of variation and not a periodogram
//
// idryx-plan.md's Phase 4 says "periodogram/autocorrelation". Those find a
// period in a signal that may contain several, which is the right tool over a
// long window with many overlapping sources. Here the input is one identity's
// connections to one destination, already separated, and the question is
// narrower: are these intervals all the same length?
//
// The coefficient of variation, standard deviation over mean, answers exactly
// that in a form an operator can check by hand from the summary, and it stays
// deterministic (invariant 1) with no windowing or FFT-bin choices to argue
// about. A periodogram here would be more machinery reaching the same verdict
// through a number nobody can reproduce mentally.
type Beaconing struct{}

func NewBeaconing() *Beaconing { return &Beaconing{} }

func (d *Beaconing) Name() string { return "beaconing" }

const (
	// beaconMinConnections is how many connections make a cadence rather than
	// a coincidence. Four gives three intervals: two can be equal by accident
	// far too easily, and three equal ones already need a reason.
	beaconMinConnections = 4

	// beaconMaxCV is how much the intervals may vary and still count as
	// regular. 0.15 admits roughly the +/-25% jitter implants use to avoid
	// looking mechanical, and rejects the irregularity of work-driven traffic.
	beaconMaxCV = 0.15

	// beaconMinInterval ignores bursts: a page opening twelve connections in a
	// second is not a heartbeat, and its intervals are regular for reasons that
	// have nothing to do with a timer.
	beaconMinInterval = 2 * time.Second
)

func (d *Beaconing) Detect(g graph.Reader) []model.Alert {
	var alerts []model.Alert

	for _, id := range g.Identities() {
		// Per destination, not per identity. One process talking to three
		// hosts has three cadences, and merging them produces intervals that
		// belong to no conversation and average into noise.
		byDest := map[string][]time.Time{}
		for _, e := range id.Events {
			if e.Type != model.EventEgress || e.Resource == "" {
				continue
			}
			byDest[e.Resource] = append(byDest[e.Resource], e.Time)
		}

		for _, dest := range sortedKeys(toSet(byDest)) {
			times := byDest[dest]
			if len(times) < beaconMinConnections {
				continue
			}
			sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

			intervals := make([]float64, 0, len(times)-1)
			for i := 1; i < len(times); i++ {
				gap := times[i].Sub(times[i-1])
				if gap < beaconMinInterval {
					intervals = nil // a burst: this destination is not on a timer
					break
				}
				intervals = append(intervals, gap.Seconds())
			}
			if len(intervals) < beaconMinConnections-1 {
				continue
			}

			mean, cv := meanAndCV(intervals)
			if cv > beaconMaxCV {
				continue
			}

			sev := model.SeverityMedium
			summary := fmt.Sprintf("%d connections to %s on a regular cadence: every %s, varying by %.0f%%. A heartbeat, not work; identify what schedules it",
				len(times), dest, roundedInterval(mean), cv*100)
			if provider, ok := matchLLM(dest); ok {
				sev = model.SeverityHigh
				summary = fmt.Sprintf("%d connections to %s (%s) on a regular cadence: every %s, varying by %.0f%%. A fixed cadence to a model API is a poll, not a conversation",
					len(times), dest, provider.display, roundedInterval(mean), cv*100)
			}

			alerts = append(alerts, model.Alert{
				Detector:   d.Name(),
				IdentityID: id.ID,
				Severity:   sev,
				Time:       now(),
				Summary:    summary,
			})
		}
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].IdentityID != alerts[j].IdentityID {
			return alerts[i].IdentityID < alerts[j].IdentityID
		}
		return alerts[i].Summary < alerts[j].Summary
	})
	return alerts
}

// meanAndCV returns the mean interval and the coefficient of variation, the
// standard deviation as a fraction of the mean.
//
// A fraction rather than an absolute spread, because regularity is relative:
// two seconds of drift on a five-second cadence is chaos, and the same two
// seconds on an hourly one is a clock being a clock. A mean of zero returns a
// CV of 1, which no threshold here accepts, rather than dividing by it.
func meanAndCV(intervals []float64) (mean, cv float64) {
	if len(intervals) == 0 {
		return 0, 1
	}
	var sum float64
	for _, v := range intervals {
		sum += v
	}
	mean = sum / float64(len(intervals))
	if mean <= 0 {
		return mean, 1
	}
	var sq float64
	for _, v := range intervals {
		sq += (v - mean) * (v - mean)
	}
	return mean, math.Sqrt(sq/float64(len(intervals))) / mean
}

// roundedInterval renders a cadence the way somebody would say it out loud, so
// the summary can be checked against a crontab without arithmetic.
func roundedInterval(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	default:
		return d.Round(100 * time.Millisecond).String()
	}
}

// toSet exists so destinations are iterated in a fixed order: map iteration in
// Go is deliberately random, and invariant 1 says the same graph produces the
// same findings in the same order.
func toSet[T any](m map[string]T) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
