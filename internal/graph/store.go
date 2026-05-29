// Package graph holds the in-memory identity graph for Phase 0. Postgres is a
// later-phase swap behind this same surface.
package graph

import (
	"sort"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Store is an in-memory collection of identities and their events.
type Store struct {
	privileged map[string]bool
	identities map[string]*model.Identity
}

// New returns a Store. The privileged set marks identities whose anomalies are
// treated as higher severity (and which the new-device detector watches).
func New(privileged map[string]bool) *Store {
	return &Store{
		privileged: privileged,
		identities: make(map[string]*model.Identity),
	}
}

// AddEvent records an event, creating the identity if needed.
func (s *Store) AddEvent(e model.Event) {
	id, ok := s.identities[e.IdentityID]
	if !ok {
		id = &model.Identity{
			ID:         e.IdentityID,
			Privileged: s.privileged[e.IdentityID],
		}
		s.identities[e.IdentityID] = id
	}
	id.Events = append(id.Events, e)
}

// Identities returns all identities sorted by ID, each with events sorted by
// time. Sorting here gives detectors a stable chronological view.
func (s *Store) Identities() []*model.Identity {
	out := make([]*model.Identity, 0, len(s.identities))
	for _, id := range s.identities {
		sort.SliceStable(id.Events, func(i, j int) bool {
			return id.Events[i].Time.Before(id.Events[j].Time)
		})
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
