package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// entraSignIn is the subset of a Microsoft Entra ID sign-in log entry that idryx
// reads. The Graph API returns these under a "value" array.
type entraSignIn struct {
	CreatedDateTime   string `json:"createdDateTime"`
	UserPrincipalName string `json:"userPrincipalName"`
	IPAddress         string `json:"ipAddress"`
	Status            struct {
		ErrorCode int `json:"errorCode"`
	} `json:"status"`
	DeviceDetail struct {
		Browser         string `json:"browser"`
		OperatingSystem string `json:"operatingSystem"`
	} `json:"deviceDetail"`
	Location struct {
		City            string `json:"city"`
		CountryOrRegion string `json:"countryOrRegion"`
		GeoCoordinates  struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"geoCoordinates"`
	} `json:"location"`
}

type entraEnvelope struct {
	Value []entraSignIn `json:"value"`
}

// Entra parses a Microsoft Entra ID sign-in log (Graph API JSON) into
// normalized events. It accepts either the {"value": [...]} envelope or a bare
// array.
func Entra(data []byte) ([]model.Event, error) {
	var env entraEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Value == nil {
		var bare []entraSignIn
		if err2 := json.Unmarshal(data, &bare); err2 != nil {
			if err != nil {
				return nil, err
			}
			return nil, err2
		}
		env.Value = bare
	}

	out := make([]model.Event, 0, len(env.Value))
	for _, r := range env.Value {
		t, err := time.Parse(time.RFC3339, r.CreatedDateTime)
		if err != nil {
			continue
		}
		outcome := "SUCCESS"
		if r.Status.ErrorCode != 0 {
			outcome = "FAILURE"
		}
		device := strings.TrimSpace(r.DeviceDetail.Browser + " " + r.DeviceDetail.OperatingSystem)
		out = append(out, model.Event{
			Time:       t,
			IdentityID: r.UserPrincipalName,
			Type:       model.EventLogin,
			Outcome:    outcome,
			IP:         r.IPAddress,
			City:       r.Location.City,
			Country:    r.Location.CountryOrRegion,
			Lat:        r.Location.GeoCoordinates.Latitude,
			Lon:        r.Location.GeoCoordinates.Longitude,
			Device:     device,
		})
	}
	return out, nil
}
