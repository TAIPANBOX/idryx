package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestAzure(t *testing.T) {
	data := []byte(`{
	  "servicePrincipals": [
	    {"id":"obj-1","appId":"app-1","displayName":"ci-deployer","accountEnabled":true,
	     "owners":["platform@x.com"],"passwordCredentialEndDates":["2023-01-01T00:00:00Z"]},
	    {"id":"obj-2","appId":"app-2","displayName":"metrics","accountEnabled":true,
	     "owners":[],"passwordCredentialEndDates":[]}
	  ],
	  "roleAssignments": [
	    {"principalId":"obj-1","roleDefinitionName":"Owner"},
	    {"principalId":"obj-2","roleDefinitionName":"Reader"},
	    {"principalId":"obj-2","roleDefinitionName":"Storage Blob Data Reader"}
	  ]
	}`)

	ids, err := Azure(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}

	byID := map[string]model.Identity{}
	for _, id := range ids {
		byID[id.ID] = id
	}

	dep := byID["azure:obj-1"]
	if dep.Type != model.IdentityServiceAccount || dep.Source != "azure" {
		t.Errorf("obj-1 type/source = %v/%q", dep.Type, dep.Source)
	}
	if dep.Owner != "platform@x.com" {
		t.Errorf("obj-1 owner = %q", dep.Owner)
	}
	if !dep.HasAdmin() || !dep.Privileged {
		t.Error("obj-1 (Owner role) should be admin/privileged")
	}
	if dep.LastUsed.IsZero() {
		t.Error("obj-1 should carry a credential-expiry timestamp")
	}

	metrics := byID["azure:obj-2"]
	if metrics.HasAdmin() {
		t.Error("obj-2 (Reader) should not be admin")
	}
	if metrics.Owner != "" {
		t.Errorf("obj-2 owner = %q, want empty", metrics.Owner)
	}
	if len(metrics.Permissions) != 2 {
		t.Errorf("obj-2 perms = %d, want 2", len(metrics.Permissions))
	}
}

func TestIsAzureAdminRole(t *testing.T) {
	cases := map[string]bool{
		"Owner":                         true,
		"Contributor":                   true,
		"User Access Administrator":     true,
		"Storage Account Administrator": true,
		"Reader":                        false,
		"Storage Blob Data Reader":      false,
	}
	for role, want := range cases {
		if got := isAzureAdminRole(role); got != want {
			t.Errorf("isAzureAdminRole(%q) = %v, want %v", role, got, want)
		}
	}
}
