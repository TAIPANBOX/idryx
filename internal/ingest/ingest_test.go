package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestEntra(t *testing.T) {
	data := []byte(`{"value":[
		{"createdDateTime":"2026-05-29T10:00:00Z","userPrincipalName":"alice@example.com",
		 "ipAddress":"1.2.3.4","status":{"errorCode":0},
		 "deviceDetail":{"browser":"Edge","operatingSystem":"Windows"},
		 "location":{"city":"Kyiv","countryOrRegion":"Ukraine","geoCoordinates":{"latitude":50.45,"longitude":30.52}}},
		{"createdDateTime":"2026-05-29T11:00:00Z","userPrincipalName":"bob@example.com",
		 "ipAddress":"5.6.7.8","status":{"errorCode":50126},
		 "deviceDetail":{"browser":"Chrome","operatingSystem":"macOS"},
		 "location":{"city":"NY","countryOrRegion":"United States","geoCoordinates":{"latitude":40.7,"longitude":-74.0}}}
	]}`)
	events, err := Entra(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].IdentityID != "alice@example.com" || events[0].Outcome != "SUCCESS" {
		t.Errorf("event0 = %+v", events[0])
	}
	if events[0].Type != model.EventLogin || events[0].Country != "Ukraine" {
		t.Errorf("event0 type/country = %v/%q", events[0].Type, events[0].Country)
	}
	if events[1].Outcome != "FAILURE" {
		t.Errorf("event1 outcome = %q, want FAILURE", events[1].Outcome)
	}
}

func TestCloudTrail(t *testing.T) {
	data := []byte(`{"Records":[
		{"eventTime":"2026-05-29T10:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"1.2.3.4",
		 "userAgent":"Mozilla","userIdentity":{"arn":"arn:aws:iam::1:user/alice","type":"IAMUser"}},
		{"eventTime":"2026-05-29T10:05:00Z","eventName":"AssumeRole","sourceIPAddress":"5.6.7.8",
		 "errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::1:role/deploy","type":"AssumedRole"}}
	]}`)
	events, err := CloudTrail(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Type != model.EventLogin || events[0].IdentityID != "arn:aws:iam::1:user/alice" {
		t.Errorf("event0 = %+v", events[0])
	}
	if events[1].Type != model.EventOther || events[1].Outcome != "FAILURE" {
		t.Errorf("event1 = %+v", events[1])
	}
}
