package detectors

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TAIPANBOX/idryx/internal/graph"
	"github.com/TAIPANBOX/idryx/internal/model"
)

func bomIncompleteGraph() *graph.Store {
	g := graph.New(nil)

	// Fully complete: owner, runtime, attestation all set -> no finding.
	g.AddIdentity(model.Identity{
		ID: "agent:complete", Type: model.IdentityAgent,
		Owner: "team-a", Runtime: "langgraph", Attestation: "spiffe-svid",
	})

	// Missing owner only.
	g.AddIdentity(model.Identity{
		ID: "agent:no-owner", Type: model.IdentityAgent,
		Runtime: "bedrock", Attestation: "oidc",
	})

	// Missing runtime only.
	g.AddIdentity(model.Identity{
		ID: "agent:no-runtime", Type: model.IdentityAgent,
		Owner: "team-b", Attestation: "oidc",
	})

	// Attestation explicitly "none" (agent-passport SPEC's honest default) is
	// still an incomplete BOM field, same treatment as attestation_missing.
	g.AddIdentity(model.Identity{
		ID: "agent:attestation-none", Type: model.IdentityAgent,
		Owner: "team-c", Runtime: "bedrock", Attestation: "none",
	})

	// Attestation unset entirely (empty string, no passport ever ingested)
	// must be treated the same as the explicit "none" above.
	g.AddIdentity(model.Identity{
		ID: "agent:attestation-unset", Type: model.IdentityAgent,
		Owner: "team-d", Runtime: "bedrock",
	})

	// Everything missing at once.
	g.AddIdentity(model.Identity{ID: "agent:bare", Type: model.IdentityAgent})

	// Non-agent NHI with nothing set -> must never be flagged; this detector
	// is agent-only (an NHI's owner/runtime gaps are orphaned_nhi's concern).
	g.AddIdentity(model.Identity{ID: "role:bare-sa", Type: model.IdentityServiceAccount})

	return g
}

func TestBOMIncomplete(t *testing.T) {
	withFixedNow(t)
	got := detect(NewBOMIncomplete(), bomIncompleteGraph())

	if _, ok := got["agent:complete"]; ok {
		t.Error("complete agent should not be flagged")
	}
	if _, ok := got["role:bare-sa"]; ok {
		t.Error("non-agent must never be flagged by bom_incomplete")
	}

	cases := map[string][]string{
		"agent:no-owner":          {"owner"},
		"agent:no-runtime":        {"runtime"},
		"agent:attestation-none":  {"attestation"},
		"agent:attestation-unset": {"attestation"},
		"agent:bare":              {"owner", "runtime", "attestation"},
	}
	for id, wantFields := range cases {
		a, ok := got[id]
		if !ok {
			t.Errorf("%s: expected a bom_incomplete finding", id)
			continue
		}
		if a.Severity != model.SeverityMedium {
			t.Errorf("%s: severity = %v, want medium", id, a.Severity)
		}
		for _, field := range wantFields {
			if !strings.Contains(a.Summary, field) {
				t.Errorf("%s: summary %q missing field %q", id, a.Summary, field)
			}
		}
	}

	// agent:no-owner is missing only "owner" -- runtime/attestation must not
	// also appear in its summary (a false extra-field claim would be its own
	// governance problem: the BOM report has to be trustworthy, not just
	// generally alarming).
	if s := got["agent:no-owner"].Summary; strings.Contains(s, "runtime") || strings.Contains(s, "attestation") {
		t.Errorf("agent:no-owner summary overclaims missing fields: %q", s)
	}
}

// TestBOMIncompleteDeterministic mirrors attestation_missing's determinism
// check: same graph, two Detect calls, identical output.
func TestBOMIncompleteDeterministic(t *testing.T) {
	withFixedNow(t)
	g := bomIncompleteGraph()
	first := NewBOMIncomplete().Detect(g)
	second := NewBOMIncomplete().Detect(g)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("non-deterministic output:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
