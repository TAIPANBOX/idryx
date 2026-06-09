package model

import "testing"

func TestIsNHI(t *testing.T) {
	cases := []struct {
		typ  IdentityType
		want bool
	}{
		{IdentityHuman, false},
		{IdentityServiceAccount, true},
		{IdentityKey, true},
		{IdentityAgent, true},
		{IdentityMCPServer, true},
	}
	for _, c := range cases {
		i := Identity{Type: c.typ}
		if got := i.IsNHI(); got != c.want {
			t.Errorf("IsNHI(%q) = %v, want %v", c.typ, got, c.want)
		}
	}
}

func TestIsAgent(t *testing.T) {
	if !(&Identity{Type: IdentityAgent}).IsAgent() {
		t.Error("agent must report IsAgent")
	}
	if (&Identity{Type: IdentityServiceAccount}).IsAgent() {
		t.Error("service account must not report IsAgent")
	}
}

func TestHasAdmin(t *testing.T) {
	none := Identity{Permissions: []Permission{{Name: "s3:Get"}, {Name: "logs:Read"}}}
	if none.HasAdmin() {
		t.Error("no admin grants → HasAdmin must be false")
	}
	admin := Identity{Permissions: []Permission{{Name: "s3:Get"}, {Name: "AdministratorAccess", Admin: true}}}
	if !admin.HasAdmin() {
		t.Error("admin grant present → HasAdmin must be true")
	}
	empty := Identity{}
	if empty.HasAdmin() {
		t.Error("empty permissions → HasAdmin must be false")
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityCritical: "critical",
		SeverityHigh:     "high",
		SeverityMedium:   "medium",
		SeverityLow:      "low",
		SeverityInfo:     "info",
		SeverityNone:     "none",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	// Report sorting relies on the numeric ordering — pin it down.
	if !(SeverityNone < SeverityInfo && SeverityInfo < SeverityLow &&
		SeverityLow < SeverityMedium && SeverityMedium < SeverityHigh &&
		SeverityHigh < SeverityCritical) {
		t.Fatal("severity ordering broken")
	}
}
