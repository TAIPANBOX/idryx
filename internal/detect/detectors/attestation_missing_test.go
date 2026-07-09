package detectors

import (
	"reflect"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func attestationGraph() *graph.Store {
	g := graph.New(nil)

	// Privileged (Privileged flag) + no attestation at all -> high.
	g.AddIdentity(model.Identity{ID: "agent:priv-unset", Type: model.IdentityAgent, Privileged: true})

	// HasAdmin (via a permission), not the Privileged flag + attestation
	// explicitly "none" -> high. Covers the "Privileged OR HasAdmin" OR and
	// the explicit "none" string separately from the zero value.
	g.AddIdentity(model.Identity{
		ID: "agent:admin-none", Type: model.IdentityAgent, Attestation: "none",
		Permissions: []model.Permission{{Name: "AdministratorAccess", Admin: true}},
	})

	// Privileged + attested (non-none) -> no finding.
	g.AddIdentity(model.Identity{ID: "agent:priv-attested", Type: model.IdentityAgent, Privileged: true, Attestation: "spiffe-svid"})

	// Unattested but not privileged/admin -> no finding (attestation gap
	// alone isn't newsworthy on a low-value identity; runaway_agent's
	// "unattested" fact still covers it if it's also spending).
	g.AddIdentity(model.Identity{ID: "agent:unattested-unprivileged", Type: model.IdentityAgent})

	// Privileged non-agent (service account) -> must never be flagged;
	// this detector is agent-only.
	g.AddIdentity(model.Identity{ID: "role:privileged-sa", Type: model.IdentityServiceAccount, Privileged: true})

	return g
}

func TestAttestationMissing(t *testing.T) {
	withFixedNow(t)
	got := detect(NewAttestationMissing(), attestationGraph())

	for _, id := range []string{"agent:priv-unset", "agent:admin-none"} {
		a, ok := got[id]
		if !ok {
			t.Errorf("%s: expected an attestation_missing finding", id)
			continue
		}
		if a.Severity != model.SeverityHigh {
			t.Errorf("%s: severity = %v, want high", id, a.Severity)
		}
	}

	for _, id := range []string{"agent:priv-attested", "agent:unattested-unprivileged", "role:privileged-sa"} {
		if a, ok := got[id]; ok {
			t.Errorf("%s: expected no attestation_missing finding, got %+v", id, a)
		}
	}
}

// TestAttestationMissingDeterministic mirrors the runaway_agent determinism
// check: same graph, two Detect calls, identical output.
func TestAttestationMissingDeterministic(t *testing.T) {
	withFixedNow(t)
	g := attestationGraph()
	first := NewAttestationMissing().Detect(g)
	second := NewAttestationMissing().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
