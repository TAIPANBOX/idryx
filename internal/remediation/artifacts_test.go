package remediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/model"
)

// TestWriteArtifactsKeepsEveryFileInsideTheDirectory: an identity id is
// producer-written text, so it must never steer a file outside dir, and two
// recommendations that sanitize to one name must both survive.
func TestWriteArtifactsKeepsEveryFileInsideTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	recs := []*Recommendation{
		{IdentityID: "../../escape", Kind: "right_size", Explanation: "e1", Code: "# one"},
		{IdentityID: "..//escape", Kind: "right_size", Explanation: "e2", Code: "# two"},
		{IdentityID: "arn:aws:iam::1:user/a b", Kind: "rotation", Explanation: "e3", Code: "# three"},
	}
	manifest, err := WriteArtifacts(dir, recs)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}

	wantFiles := []string{
		"right_size__.._.._escape.tf",
		"right_size__..__escape.tf",
		"rotation__arn_aws_iam__1_user_a_b.tf",
	}
	var gotFiles []string
	for _, a := range manifest {
		gotFiles = append(gotFiles, a.File)
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("files = %v, want %v", gotFiles, wantFiles)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(recs)+1 {
		t.Errorf("dir holds %d entries, want %d artifacts + manifest.json", len(entries), len(recs))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.tf")); err == nil {
		t.Error("an artifact escaped the output directory")
	}

	body, err := os.ReadFile(filepath.Join(dir, wantFiles[2]))
	if err != nil || string(body) != "# three\n" {
		t.Errorf("artifact body = %q, %v; want the code plus a newline", body, err)
	}

	var onDisk []Artifact
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("manifest.json is not JSON: %v", err)
	}
	if !reflect.DeepEqual(onDisk, manifest) {
		t.Errorf("manifest on disk %+v differs from the one returned %+v", onDisk, manifest)
	}
	if onDisk[0].Identity != "../../escape" || onDisk[0].Explanation != "e1" {
		t.Errorf("the manifest must keep the real identity id and explanation: %+v", onDisk[0])
	}
}

func TestWriteArtifactsNumbersRepeatedNames(t *testing.T) {
	recs := []*Recommendation{
		{IdentityID: "agent:x", Kind: "rotation", Code: "a"},
		{IdentityID: "agent:x", Kind: "rotation", Code: "b"},
		{IdentityID: "agent:x", Kind: "rotation", Code: "c"},
	}
	manifest, err := WriteArtifacts(t.TempDir(), recs)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}
	var got []string
	for _, a := range manifest {
		got = append(got, a.File)
	}
	want := []string{"rotation__agent_x.tf", "rotation__agent_x_2.tf", "rotation__agent_x_3.tf"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
}

func TestWriteArtifactsWithNothingWritesAnEmptyManifest(t *testing.T) {
	dir := t.TempDir()
	manifest, err := WriteArtifacts(dir, nil)
	if err != nil || len(manifest) != 0 {
		t.Fatalf("WriteArtifacts(nil) = %v, %v", manifest, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil || strings.TrimSpace(string(data)) != "[]" {
		t.Errorf("manifest.json = %q, %v; want an empty JSON list", data, err)
	}
}

func TestWriteArtifactsReportsADirectoryItCannotCreate(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteArtifacts(filepath.Join(blocker, "sub"), []*Recommendation{{IdentityID: "a", Kind: "k"}}); err == nil {
		t.Fatal("expected an error creating a directory under a regular file")
	}
}

func TestSanitizeNameKeepsOnlyFilenameSafeRunes(t *testing.T) {
	cases := map[string]string{
		"Agent-01_x.y":           "Agent-01_x.y",
		"a/b\\c":                 "a_b_c",
		"user@example.com":       "user_example.com",
		"\x00ëñ":                 "___",
		"serviceAccount:sa@p.io": "serviceAccount_sa_p.io",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGenerateFallsBackToAGenericListForOtherSources: a source with no
// provider-specific template still gets its unused grants named.
func TestGenerateFallsBackToAGenericListForOtherSources(t *testing.T) {
	rec := Generate(model.Identity{
		ID: "svc:robot", Source: "mcp",
		Permissions: []model.Permission{{Name: "tool:read", Used: true}, {Name: "tool:delete"}, {Name: "tool:admin"}},
	})
	if rec == nil {
		t.Fatal("no recommendation for two unused grants")
	}
	for _, want := range []string{"# Generic Remediation for svc:robot (mcp)", "- tool:delete", "- tool:admin"} {
		if !strings.Contains(rec.Code, want) {
			t.Errorf("code missing %q:\n%s", want, rec.Code)
		}
	}
	if strings.Contains(rec.Code, "tool:read") {
		t.Errorf("a used grant was listed for revocation:\n%s", rec.Code)
	}
	if !strings.HasPrefix(rec.Explanation, "2 of 3 granted permissions") {
		t.Errorf("explanation = %q", rec.Explanation)
	}
}

func TestGenerateRotationSkipsASourceWithNoRotatableSecret(t *testing.T) {
	old := now
	now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { now = old }()
	id := model.Identity{ID: "svc:x", Type: model.IdentityServiceAccount, Source: "okta", Created: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
	if rec := GenerateRotation(id); rec != nil {
		t.Errorf("rotation proposed for a source with no rotation template: %+v", rec)
	}
}

// TestGenerateAWSNamesTheRoleFromAColonOnlyID: an id with no path still
// yields the bare role name, not the whole ARN.
func TestGenerateAWSNamesTheRoleFromAColonOnlyID(t *testing.T) {
	rec := Generate(model.Identity{
		ID: "arn:aws:iam::123:deployer", Source: "aws_iam",
		Permissions: []model.Permission{{Name: "A", Used: true}, {Name: "B"}},
	})
	if rec == nil || !strings.Contains(rec.Code, `role       = "deployer"`) {
		t.Fatalf("role name not taken from after the last colon:\n%v", rec)
	}
	if got := lastSegment("plainname"); got != "plainname" {
		t.Errorf("lastSegment(plainname) = %q", got)
	}
	if got := lastSegment("a:b:c"); got != "c" {
		t.Errorf("lastSegment(a:b:c) = %q, want c", got)
	}
}
