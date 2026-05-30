package ingest

import (
	"testing"

	"github.com/TAIPANBOX/idryx/internal/model"
)

func TestGCPIAM(t *testing.T) {
	data := []byte(`{
	  "serviceAccounts": [
	    {"email":"deploy@proj.iam.gserviceaccount.com","displayName":"owner: platform"},
	    {"email":"reader@proj.iam.gserviceaccount.com","displayName":"telemetry reader"}
	  ],
	  "policy": {
	    "bindings": [
	      {"role":"roles/owner","members":["serviceAccount:deploy@proj.iam.gserviceaccount.com","user:human@x.com"]},
	      {"role":"roles/logging.viewer","members":["serviceAccount:reader@proj.iam.gserviceaccount.com"]},
	      {"role":"roles/storage.admin","members":["serviceAccount:reader@proj.iam.gserviceaccount.com"]}
	    ]
	  }
	}`)

	ids, err := GCPIAM(data)
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

	deploy := byID["gcp:deploy@proj.iam.gserviceaccount.com"]
	if deploy.Type != model.IdentityServiceAccount || deploy.Source != "gcp_iam" {
		t.Errorf("deploy type/source = %v/%q", deploy.Type, deploy.Source)
	}
	if deploy.Owner != "platform" {
		t.Errorf("deploy owner = %q, want platform", deploy.Owner)
	}
	if !deploy.HasAdmin() || !deploy.Privileged {
		t.Error("deploy (roles/owner) should be admin/privileged")
	}

	reader := byID["gcp:reader@proj.iam.gserviceaccount.com"]
	if len(reader.Permissions) != 2 {
		t.Fatalf("reader perms = %d, want 2", len(reader.Permissions))
	}
	// roles/storage.admin must be flagged admin; roles/logging.viewer must not.
	if !reader.HasAdmin() {
		t.Error("reader should be admin via roles/storage.admin")
	}
}

func TestIsAdminRole(t *testing.T) {
	cases := map[string]bool{
		"roles/owner":          true,
		"roles/editor":         true,
		"roles/storage.admin":  true,
		"roles/iam.admin":      true,
		"roles/logging.viewer": false,
		"roles/viewer":         false,
	}
	for role, want := range cases {
		if got := isAdminRole(role); got != want {
			t.Errorf("isAdminRole(%q) = %v, want %v", role, got, want)
		}
	}
}
