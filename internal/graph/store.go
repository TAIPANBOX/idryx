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
	seenEvents map[model.Event]bool
}

// New returns a Store. The privileged set marks identities whose anomalies are
// treated as higher severity (and which the new-device detector watches).
func New(privileged map[string]bool) *Store {
	return &Store{
		privileged: privileged,
		identities: make(map[string]*model.Identity),
		seenEvents: make(map[model.Event]bool),
	}
}

// AddEvent records an event, creating the identity if needed. Re-adding an
// event identical in every field (the natural key: identity, time, type, and
// every other recorded detail) is a no-op, so replaying a source file (e.g.
// `idryx load --source okta okta.json` run twice, or the same file named in
// --load more than once) cannot double-count events and inflate threshold
// detectors like mfa_fatigue. model.Event has only comparable fields, so it
// can be used directly as a set key.
func (s *Store) AddEvent(e model.Event) {
	if s.seenEvents[e] {
		return
	}
	s.seenEvents[e] = true
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
	if len(in.OnBehalfOf) > 0 {
		id.OnBehalfOf = append([]string(nil), in.OnBehalfOf...)
	}
	if in.Parent != "" {
		id.Parent = in.Parent
	}
	if in.Attestation != "" {
		id.Attestation = in.Attestation
	}
	if len(in.DeclaredModels) > 0 {
		id.DeclaredModels = append([]model.DeclaredModel(nil), in.DeclaredModels...)
	}
	if in.Shadow {
		id.Shadow = true
	}
	id.Permissions = append(id.Permissions, in.Permissions...)
	id.Events = append(id.Events, in.Events...)
}

// DelegationChain returns the chain of identity IDs an agent acts through,
// starting at id and following OnBehalfOf upward to the ultimate principal.
// The starting id is included first, then each principal in id's own chain
// (walked immediate-principal-first, i.e. OnBehalfOf in reverse, since that
// array is stored root-first per agent-passport SPEC §5). If the root of that
// chain is itself a graph identity with a further OnBehalfOf chain of its own
// (e.g. reconstructed hop-by-hop from an inventory source), the walk
// continues from there — so a chain can be assembled either from one
// identity's fully-populated array (an event source that never truncates it)
// or by stitching one-hop links across several identities (an inventory
// source), or a mix of both. A cycle or missing link terminates the walk.
func (s *Store) DelegationChain(id string) []string {
	return WalkDelegationChain(s.identities, id)
}

// WalkDelegationChain is the backend-agnostic implementation shared with the
// excessive_agency detector, which indexes graph.Reader identities itself
// (it can't reuse *Store directly, since it must also work over PgStore
// snapshots and any future graph.Reader backend).
func WalkDelegationChain(index map[string]*model.Identity, start string) []string {
	var chain []string
	seen := map[string]bool{}
	add := func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		chain = append(chain, id)
		return true
	}

	if !add(start) {
		return chain
	}
	for cur := start; ; {
		node, ok := index[cur]
		if !ok {
			break
		}
		// Append this node's own chain, immediate principal first (i.e. its
		// OnBehalfOf array in reverse — that array is root-first per
		// agent-passport SPEC §5). Continue the outer walk from the root of
		// this array, in case that root is itself a node with a further
		// chain to stitch on (the inventory-source case: one hop per node).
		next := ""
		for i := len(node.OnBehalfOf) - 1; i >= 0; i-- {
			if p := node.OnBehalfOf[i]; add(p) {
				next = p
			}
		}
		if next == "" {
			break
		}
		cur = next
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

// BlastRadius returns the de-duplicated (by permission name, first occurrence
// wins — the starting identity's own grant of a name shadows a same-named
// grant further up the chain) union of permissions reachable from start
// through WalkDelegationChain. It is the backend-agnostic, index-based
// counterpart to EffectivePermissions: detectors that depend only on
// graph.Reader (not the concrete *Store, e.g. runaway_agent) index the
// identities they're given and call this directly, so there is exactly one
// delegation walker (WalkDelegationChain) and one blast-radius definition,
// shared by the in-memory Store, the dashboard's size metric, and detectors.
func BlastRadius(index map[string]*model.Identity, start string) []model.Permission {
	seen := map[string]bool{}
	var out []model.Permission
	for _, link := range WalkDelegationChain(index, start) {
		node, ok := index[link]
		if !ok {
			continue
		}
		for _, p := range node.Permissions {
			if seen[p.Name] {
				continue
			}
			seen[p.Name] = true
			out = append(out, p)
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
