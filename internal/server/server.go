// Package server exposes the identity graph and alerts over a read-only HTTP
// API plus a minimal HTML dashboard. It is read-only by design: idryx observes,
// it does not mutate the IdP.
package server

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// Server holds the data rendered by the API and dashboard. It is a snapshot:
// the graph and alerts are computed once by the caller and served read-only.
type Server struct {
	graph    graph.Reader
	alerts   []model.Alert
	remParam []*remediation.Recommendation // when non-nil, served instead of recomputing
}

// New returns a Server over the given graph and precomputed alerts.
func New(g graph.Reader, alerts []model.Alert) *Server {
	return &Server{graph: g, alerts: alerts}
}

// SetRemediations makes /api/remediations serve a fixed set (e.g. recommendations
// loaded from Postgres) instead of recomputing them from the graph. Passing a
// nil slice restores the recompute-from-graph default.
func (s *Server) SetRemediations(recs []*remediation.Recommendation) {
	s.remParam = recs
}

// Handler returns the HTTP routes: dashboard at /, JSON at /api/*.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/identities", s.handleIdentities)
	mux.HandleFunc("/api/remediations", s.handleRemediations)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handleDashboard)
	return mux
}

type apiAlert struct {
	Detector string `json:"detector"`
	Identity string `json:"identity"`
	Severity string `json:"severity"`
	Time     string `json:"time"`
	Summary  string `json:"summary"`
}

func (s *Server) alertsJSON() []apiAlert {
	out := make([]apiAlert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, apiAlert{
			Detector: a.Detector,
			Identity: a.IdentityID,
			Severity: a.Severity.String(),
			Time:     a.Time.UTC().Format("2006-01-02T15:04:05Z"),
			Summary:  a.Summary,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Time < out[j].Time
	})
	return out
}

func (s *Server) handleAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.alertsJSON())
}

type apiPermission struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	Used  bool   `json:"used"`
}

type apiRemediation struct {
	Kind        string `json:"kind"`
	Explanation string `json:"explanation"`
	Code        string `json:"code"`
}

// apiRecommendation is a flat, identity-tagged remediation for the
// /api/remediations endpoint (one row per recommendation, ready for SOAR).
type apiRecommendation struct {
	Identity    string `json:"identity"`
	Kind        string `json:"kind"`
	Explanation string `json:"explanation"`
	Code        string `json:"code"`
}

type apiIdentity struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Privileged  bool            `json:"privileged"`
	Source      string          `json:"source"`
	Owner       string          `json:"owner"`
	Created     string          `json:"created,omitempty"`
	LastUsed    string          `json:"last_used,omitempty"`
	Runtime     string          `json:"runtime,omitempty"`
	OnBehalfOf  string          `json:"on_behalf_of,omitempty"`
	Permissions []apiPermission `json:"permissions,omitempty"`
	Remediation *apiRemediation `json:"remediation,omitempty"`
	Rotation    *apiRemediation `json:"rotation,omitempty"`
	Events      int             `json:"events"`
	Alerts      int             `json:"alerts"`
}

func (s *Server) identitiesJSON() []apiIdentity {
	alertCount := map[string]int{}
	for _, a := range s.alerts {
		alertCount[a.IdentityID]++
	}
	ids := s.graph.Identities()
	out := make([]apiIdentity, 0, len(ids))
	for _, id := range ids {
		var perms []apiPermission
		for _, p := range id.Permissions {
			perms = append(perms, apiPermission{
				Name:  p.Name,
				Admin: p.Admin,
				Used:  p.Used,
			})
		}

		createdStr := ""
		if !id.Created.IsZero() {
			createdStr = id.Created.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		lastUsedStr := ""
		if !id.LastUsed.IsZero() {
			lastUsedStr = id.LastUsed.UTC().Format("2006-01-02 15:04:05 UTC")
		}

		typStr := string(id.Type)
		if typStr == "" {
			typStr = "human"
		}

		var remData *apiRemediation
		if rem := remediation.Generate(*id); rem != nil {
			remData = &apiRemediation{
				Kind:        rem.Kind,
				Explanation: rem.Explanation,
				Code:        rem.Code,
			}
		}
		var rotData *apiRemediation
		if rem := remediation.GenerateRotation(*id); rem != nil {
			rotData = &apiRemediation{
				Kind:        rem.Kind,
				Explanation: rem.Explanation,
				Code:        rem.Code,
			}
		}

		out = append(out, apiIdentity{
			ID:          id.ID,
			Type:        typStr,
			Privileged:  id.Privileged,
			Source:      id.Source,
			Owner:       id.Owner,
			Created:     createdStr,
			LastUsed:    lastUsedStr,
			Runtime:     id.Runtime,
			OnBehalfOf:  id.OnBehalfOf,
			Permissions: perms,
			Remediation: remData,
			Rotation:    rotData,
			Events:      len(id.Events),
			Alerts:      alertCount[id.ID],
		})
	}
	return out
}

func (s *Server) handleIdentities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.identitiesJSON())
}

func (s *Server) remediationsJSON() []apiRecommendation {
	out := make([]apiRecommendation, 0)
	// Prefer a persisted set when one was supplied (serve --db).
	if s.remParam != nil {
		for _, rem := range s.remParam {
			out = append(out, apiRecommendation{Identity: rem.IdentityID, Kind: rem.Kind, Explanation: rem.Explanation, Code: rem.Code})
		}
		return out
	}
	for _, id := range s.graph.Identities() {
		if rem := remediation.Generate(*id); rem != nil {
			out = append(out, apiRecommendation{Identity: id.ID, Kind: rem.Kind, Explanation: rem.Explanation, Code: rem.Code})
		}
		if rem := remediation.GenerateRotation(*id); rem != nil {
			out = append(out, apiRecommendation{Identity: id.ID, Kind: rem.Kind, Explanation: rem.Explanation, Code: rem.Code})
		}
	}
	return out
}

func (s *Server) handleRemediations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.remediationsJSON())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
