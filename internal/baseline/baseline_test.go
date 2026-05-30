package baseline

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func login(day int, country, device string, hour int) model.Event {
	return model.Event{
		Time:    time.Date(2026, 5, day, hour, 0, 0, 0, time.UTC),
		Type:    model.EventLogin,
		Outcome: "SUCCESS",
		Country: country,
		Device:  device,
	}
}

func TestScoreLearnsNormalAndFlagsAnomaly(t *testing.T) {
	id := &model.Identity{ID: "alice@example.com"}
	// Six normal logins from Ukraine on the same device, business hours.
	for d := 1; d <= 6; d++ {
		id.Events = append(id.Events, login(d, "Ukraine", "Chrome macOS", 9))
	}
	p := Build(id)

	// A repeat of normal behavior scores ~0.
	if s := p.Score(login(7, "Ukraine", "Chrome macOS", 9)); s > 0.1 {
		t.Errorf("normal login scored %.2f, want ~0", s)
	}

	// New country + new device + odd hour scores high.
	if s := p.Score(login(7, "Brazil", "Firefox Windows", 3)); s < anHigh {
		t.Errorf("anomalous login scored %.2f, want >= %.2f", s, anHigh)
	}
}

const anHigh = 0.6

func TestScoreSuppressedDuringLearning(t *testing.T) {
	id := &model.Identity{ID: "bob@example.com"}
	// Only two logins — below minLoginsToScore, so nothing is trusted yet.
	id.Events = append(id.Events, login(1, "Ukraine", "Chrome", 9))
	id.Events = append(id.Events, login(2, "Ukraine", "Chrome", 9))
	p := Build(id)
	if s := p.Score(login(3, "Brazil", "Firefox", 3)); s != 0 {
		t.Errorf("score during learning = %.2f, want 0", s)
	}
}
