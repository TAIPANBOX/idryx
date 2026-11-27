package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// TestAlertsSortBySeverityThenTime covers every rank: the dashboard puts the
// worst first, and within one severity the earliest first.
func TestAlertsSortBySeverityThenTime(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	alerts := []model.Alert{
		{Detector: "d-none", Severity: model.SeverityNone, Time: t0},
		{Detector: "d-info", Severity: model.SeverityInfo, Time: t0},
		{Detector: "d-low", Severity: model.SeverityLow, Time: t0},
		{Detector: "d-high-late", Severity: model.SeverityHigh, Time: t0.Add(time.Hour)},
		{Detector: "d-medium", Severity: model.SeverityMedium, Time: t0},
		{Detector: "d-critical", Severity: model.SeverityCritical, Time: t0},
		{Detector: "d-high-early", Severity: model.SeverityHigh, Time: t0},
	}
	rr := get(t, New(graph.New(nil), alerts).Handler(), "/api/alerts")
	var got []apiAlert
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, a := range got {
		order = append(order, a.Detector)
	}
	want := []string{"d-critical", "d-high-early", "d-high-late", "d-medium", "d-low", "d-info", "d-none"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// TestIdentitiesShowTimesTypesAndPersistedRemediationTimes: a human is shown
// as "human", known times are rendered in UTC, unknown ones are omitted, and
// a persisted remediation carries the time it was generated while an entry
// with no recommendation or no time is ignored.
func TestIdentitiesShowTimesTypesAndPersistedRemediationTimes(t *testing.T) {
	created := time.Date(2020, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	used := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "arn:aws:iam::1:user/etl", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Created: created, LastUsed: used,
		Permissions: []model.Permission{{Name: "A", Used: true}, {Name: "B", Admin: true}},
	})
	g.AddEvent(model.Event{IdentityID: "dana@x.com", Type: model.EventLogin, Time: used})

	srv := New(g, nil)
	gen := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	srv.SetRemediations([]graph.StoredRemediation{
		{Recommendation: &remediation.Recommendation{IdentityID: "arn:aws:iam::1:user/etl", Kind: "right_size"}, CreatedAt: gen},
		{Recommendation: nil, CreatedAt: gen},
		{Recommendation: &remediation.Recommendation{IdentityID: "arn:aws:iam::1:user/etl", Kind: "rotation"}},
	})

	rr := get(t, srv.Handler(), "/api/identities")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var got []apiIdentity
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	byID := map[string]apiIdentity{}
	for _, id := range got {
		byID[id.ID] = id
	}

	role := byID["arn:aws:iam::1:user/etl"]
	if role.Created != "2020-01-02 02:04:05 UTC" || role.LastUsed != "2026-01-02 03:04:05 UTC" {
		t.Errorf("times = %q / %q, want both in UTC", role.Created, role.LastUsed)
	}
	if role.Type != "service_account" {
		t.Errorf("type = %q", role.Type)
	}
	if role.Remediation == nil || role.Remediation.CreatedAt != "2026-02-03 04:05:06 UTC" {
		t.Errorf("right-size remediation = %+v, want it stamped with the persisted time", role.Remediation)
	}
	if role.Rotation == nil || role.Rotation.Kind != "rotation" || role.Rotation.CreatedAt != "" {
		t.Errorf("rotation = %+v, want one with no time, since its persisted entry had none", role.Rotation)
	}

	human := byID["dana@x.com"]
	if human.Type != "human" {
		t.Errorf("a human is shown as %q, want human", human.Type)
	}
	if human.Created != "" || human.LastUsed != "" {
		t.Errorf("unknown times rendered as %q / %q, want them omitted", human.Created, human.LastUsed)
	}
	if human.Remediation != nil || human.Rotation != nil {
		t.Errorf("a human with no grants got remediations: %+v / %+v", human.Remediation, human.Rotation)
	}
}

// TestRemediationsFromTheGraphListBothKinds: with nothing persisted, the
// endpoint recomputes from the graph and lists right-size and rotation.
func TestRemediationsFromTheGraphListBothKinds(t *testing.T) {
	g := graph.New(nil)
	g.AddIdentity(model.Identity{
		ID: "arn:aws:iam::1:user/old", Type: model.IdentityServiceAccount, Source: "aws_iam",
		Created:     time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		Permissions: []model.Permission{{Name: "A", Used: true}, {Name: "B"}},
	})
	rr := get(t, New(g, nil).Handler(), "/api/remediations")
	var got []apiRecommendation
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range got {
		if r.Identity != "arn:aws:iam::1:user/old" {
			t.Errorf("unexpected identity %q", r.Identity)
		}
		kinds = append(kinds, r.Kind)
	}
	if !reflect.DeepEqual(kinds, []string{"right_size", "rotation"}) {
		t.Errorf("kinds = %v, want right_size then rotation", kinds)
	}
}
