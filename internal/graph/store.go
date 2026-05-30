// Package graph holds the identity graph. Phase 0/1 use an in-memory Store; a
// Postgres-backed implementation can satisfy the same Reader interface later
// without touching detectors.
package graph

import (
	"sort"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// Reader is the read surface detectors depend on. Any backend (in-memory,
// Postgres) that returns identities with chronological events satisfies it.
type Reader interface {
	// Identities returns all identities, each with events in chronological order.
	Identities() []*model.Identity
}

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
	id := s.ensure(e.IdentityID)
	id.Events = append(id.Events, e)
}

// AddIdentity merges a fully-described identity (e.g. an NHI from an IAM
// connector) into the graph. Metadata fields are filled in; events from other
// sources on the same ID are preserved.
func (s *Store) AddIdentity(in model.Identity) {
	id := s.ensure(in.ID)
	if in.Type != model.IdentityHuman {
		id.Type = in.Type
	}
	if in.Source != "" {
		id.Source = in.Source
	}
	if in.Owner != "" {
		id.Owner = in.Owner
	}
	if !in.Created.IsZero() {
		id.Created = in.Created
	}
	if in.LastUsed.After(id.LastUsed) {
		id.LastUsed = in.LastUsed
	}
	if in.Privileged {
		id.Privileged = true
	}
	if in.Runtime != "" {
		id.Runtime = in.Runtime
	}
	if in.OnBehalfOf != "" {
		id.OnBehalfOf = in.OnBehalfOf
	}
	id.Permissions = append(id.Permissions, in.Permissions...)
	id.Events = append(id.Events, in.Events...)
}

// DelegationChain returns the chain of identity IDs an agent acts through,
// starting at id and following OnBehalfOf upward to the ultimate principal.
// The starting id is included; a cycle or missing link terminates the walk.
func (s *Store) DelegationChain(id string) []string {
	var chain []string
	seen := map[string]bool{}
	for cur := id; cur != ""; {
		if seen[cur] {
			break // cycle guard
		}
		seen[cur] = true
		chain = append(chain, cur)
		node, ok := s.identities[cur]
		if !ok {
			break
		}
		cur = node.OnBehalfOf
	}
	return chain
}

// EffectivePermissions returns the union of permissions an agent reaches through
// its delegation chain: an agent's blast radius is the sum of what every
// identity it can act as is allowed to do.
func (s *Store) EffectivePermissions(id string) []model.Permission {
	var out []model.Permission
	for _, link := range s.DelegationChain(id) {
		if node, ok := s.identities[link]; ok {
			out = append(out, node.Permissions...)
		}
	}
	return out
}

// ensure returns the identity for id, creating it (with the privileged flag
// applied) if absent.
func (s *Store) ensure(id string) *model.Identity {
	got, ok := s.identities[id]
	if !ok {
		got = &model.Identity{ID: id, Privileged: s.privileged[id]}
		s.identities[id] = got
	}
	return got
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
