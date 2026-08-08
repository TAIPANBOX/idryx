package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/ebpfcapture"
	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

// egressAt is egress() with an explicit time, which is the whole subject here.
func egressAt(identity, dest string, at time.Time) model.Event {
	e := egress(identity, dest)
	e.Time = at
	return e
}

// beat adds n connections spaced by every, with each interval offset by the
// matching jitter fraction, so a test can say "a 60s beacon with 10% jitter"
// rather than hand-writing timestamps.
func beat(g *graph.Store, identity, dest string, start time.Time, every time.Duration, n int, jitter []float64) {
	at := start
	for i := 0; i < n; i++ {
		g.AddEvent(egressAt(identity, dest, at))
		step := every
		if i < len(jitter) {
			step = time.Duration(float64(every) * (1 + jitter[i]))
		}
		at = at.Add(step)
	}
}

func TestBeaconingFindsARegularCadenceAndIgnoresIrregularWork(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	g := graph.New(nil)

	// A clean 60-second heartbeat with small jitter: the case this exists for.
	beat(g, "proc:agent@cg1", "203.0.113.10:443", start, time.Minute, 6,
		[]float64{0.02, -0.03, 0.01, -0.02, 0.03})

	// Work-driven traffic: same count, same window, irregular gaps.
	at := start
	for _, gap := range []time.Duration{3 * time.Second, 47 * time.Second, 5 * time.Second, 2 * time.Minute, 11 * time.Second} {
		g.AddEvent(egressAt("proc:worker@cg2", "203.0.113.20:443", at))
		at = at.Add(gap)
	}
	g.AddEvent(egressAt("proc:worker@cg2", "203.0.113.20:443", at))

	got := detect(NewBeaconing(), g)

	a, ok := got["proc:agent@cg1"]
	if !ok {
		t.Fatal("a 60s cadence with 3% jitter must be flagged")
	}
	if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium for an ordinary destination", a.Severity)
	}
	// The summary must carry the cadence: an operator's first move is to check
	// it against their own schedules, and "every 1m0s" is checkable, "beaconing
	// detected" is not.
	if !strings.Contains(a.Summary, "1m0s") {
		t.Errorf("summary does not state the cadence: %q", a.Summary)
	}

	if _, ok := got["proc:worker@cg2"]; ok {
		t.Error("irregular, work-driven traffic must not be flagged; this is the false positive that gets a detector switched off")
	}
}

// A fixed cadence to a model API is a poll rather than a conversation, which is
// worth one band more.
func TestACadenceToAModelAPIOutranksAnOrdinaryHost(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	g := graph.New(nil)
	beat(g, ebpfcapture.Identity("python3", 7), "api.openai.com:443", start, 30*time.Second, 5, nil)

	got := detect(NewBeaconing(), g)
	a, ok := got[ebpfcapture.Identity("python3", 7)]
	if !ok {
		t.Fatal("a cadence to a known LLM API must be flagged")
	}
	if a.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high for a model API", a.Severity)
	}
}

// Three connections give two intervals, and two intervals are equal far too
// easily by accident. Four is where a cadence starts being a claim.
func TestThreeConnectionsAreNotYetACadence(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	g := graph.New(nil)
	beat(g, "proc:x@cg1", "203.0.113.30:443", start, time.Minute, 3, nil)

	if got := detect(NewBeaconing(), g); len(got) != 0 {
		t.Errorf("three connections were reported as a cadence: %v", got)
	}
}

// A burst is regular for reasons that have nothing to do with a timer: a page
// opening a dozen sockets at once has near-identical intervals and is not a
// heartbeat.
func TestABurstIsNotABeacon(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	g := graph.New(nil)
	beat(g, "proc:browser@cg3", "203.0.113.40:443", start, 200*time.Millisecond, 8, nil)

	if got := detect(NewBeaconing(), g); len(got) != 0 {
		t.Errorf("a sub-second burst was reported as a beacon: %v", got)
	}
}

// One identity talking to two hosts has two cadences. Merging them produces
// intervals belonging to no conversation, which average into noise and hide
// both.
func TestTwoDestinationsAreTwoCadencesNotOne(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	g := graph.New(nil)
	// Interleaved on purpose: merged, the gaps alternate 10s/50s and look
	// irregular, so a per-identity implementation would find nothing at all.
	beat(g, "proc:multi@cg4", "203.0.113.50:443", start, time.Minute, 5, nil)
	beat(g, "proc:multi@cg4", "203.0.113.60:443", start.Add(10*time.Second), time.Minute, 5, nil)

	got := detect(NewBeaconing(), g)
	if _, ok := got["proc:multi@cg4"]; !ok {
		t.Fatal("two interleaved cadences from one identity produced no finding at all")
	}
}

// The jitter threshold is the whole judgement of this detector, so both sides
// of it are pinned: an implant's deliberate jitter is still a beacon, and
// genuinely variable traffic is not.
func TestTheJitterThresholdHoldsBothWays(t *testing.T) {
	withFixedNow(t)
	start := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)

	within := graph.New(nil)
	beat(within, "proc:a@cg1", "203.0.113.70:443", start, time.Minute, 6,
		[]float64{0.10, -0.10, 0.08, -0.09, 0.10})
	if got := detect(NewBeaconing(), within); len(got) != 1 {
		t.Errorf("10%% jitter is still a beacon; got %d findings", len(got))
	}

	beyond := graph.New(nil)
	beat(beyond, "proc:b@cg1", "203.0.113.80:443", start, time.Minute, 6,
		[]float64{0.6, -0.5, 0.7, -0.4, 0.55})
	if got := detect(NewBeaconing(), beyond); len(got) != 0 {
		t.Errorf("traffic varying by half its period is not a cadence; got %v", got)
	}
}
