package enforce

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// fakeRunner records every command and returns canned output, so the git/gh
// sequence can be asserted without invoking real binaries.
type fakeRunner struct {
	calls [][]string
	out   map[string]string // keyed by the first two args, e.g. "gh pr"
	err   map[string]error
}

func (f *fakeRunner) Run(_ context.Context, _ string, name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	key := name
	if len(args) > 0 {
		key = name + " " + args[0]
	}
	return f.out[key], f.err[key]
}

func sampleRecs() []*remediation.Recommendation {
	return []*remediation.Recommendation{
		{IdentityID: "arn:aws:iam::1:role/etl", Kind: "right_size", Explanation: "2 unused", Code: "- policy a"},
		{IdentityID: "arn:aws:iam::1:user/deploy", Kind: "rotation", Explanation: "old key", Code: "rotate"},
	}
}

func TestOpenPRSequenceAndArtifacts(t *testing.T) {
	old := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = old }()

	repo := t.TempDir()
	f := &fakeRunner{
		out: map[string]string{"gh pr": "https://github.com/acme/iac/pull/42\n"},
	}

	url, err := OpenPR(context.Background(), f, sampleRecs(), Options{RepoDir: repo})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if url != "https://github.com/acme/iac/pull/42" {
		t.Errorf("url = %q, want the gh stdout trimmed", url)
	}

	// Expected command order: preflight (rev-parse, status, gh auth), then
	// checkout -b, add, commit, push, gh pr create.
	wantOrder := []string{
		"git rev-parse", "git status", "gh auth",
		"git checkout", "git add", "git commit", "git push", "gh pr",
	}
	if len(f.calls) != len(wantOrder) {
		t.Fatalf("got %d calls, want %d: %v", len(f.calls), len(wantOrder), f.calls)
	}
	for i, w := range wantOrder {
		got := f.calls[i][0] + " " + f.calls[i][1]
		if got != w {
			t.Errorf("call %d = %q, want %q", i, got, w)
		}
	}

	// Deterministic branch name flows into checkout (git checkout -b <branch>),
	// push, and gh --head. checkout is the 4th call (index 3) after preflight.
	branch := "idryx/remediation-" + strconv.FormatInt(nowFunc().Unix(), 10)
	if f.calls[3][3] != branch {
		t.Errorf("checkout branch = %q, want %q", f.calls[3][3], branch)
	}
	gh := strings.Join(f.calls[7], " ")
	if !strings.Contains(gh, "--head "+branch) || !strings.Contains(gh, "--base main") {
		t.Errorf("gh pr create missing head/base: %q", gh)
	}
	if !strings.Contains(gh, "--title") || !strings.Contains(gh, "--body") {
		t.Errorf("gh pr create missing title/body: %q", gh)
	}

	// Artifacts were written into <repo>/idryx with a manifest.
	if _, err := os.Stat(filepath.Join(repo, "idryx", "manifest.json")); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(repo, "idryx"))
	if len(entries) != 3 { // 2 .tf + manifest.json
		t.Errorf("got %d artifact files, want 3", len(entries))
	}
}

func TestOpenPRBodyMentionsReadOnly(t *testing.T) {
	body := defaultBody(sampleRecs())
	if !strings.Contains(body, "read-only") {
		t.Error("PR body should state idryx is read-only")
	}
	if !strings.Contains(body, "arn:aws:iam::1:role/etl") {
		t.Error("PR body should list each remediation identity")
	}
	if strings.Contains(body, "Review the Terraform under the artifacts directory and apply via your normal plan/apply workflow.") {
		t.Error("PR body still claims the generated Terraform is directly apply-able")
	}
	if !strings.Contains(body, "proposed diff") {
		t.Error("PR body should tell the reviewer the artifacts are a proposed diff, not a drop-in file")
	}
}

func TestOpenPRGuards(t *testing.T) {
	f := &fakeRunner{}
	if _, err := OpenPR(context.Background(), f, nil, Options{RepoDir: "/tmp"}); err == nil {
		t.Error("expected error for empty recs")
	}
	if _, err := OpenPR(context.Background(), f, sampleRecs(), Options{}); err == nil {
		t.Error("expected error for missing RepoDir")
	}
	if len(f.calls) != 0 {
		t.Errorf("guards must run before any command, got %v", f.calls)
	}
}

func TestOpenPRPreflightAborts(t *testing.T) {
	// A dirty work tree must abort before any branch is created.
	dirty := &fakeRunner{out: map[string]string{"git status": " M main.tf"}}
	if _, err := OpenPR(context.Background(), dirty, sampleRecs(), Options{RepoDir: t.TempDir()}); err == nil {
		t.Error("expected error for a dirty IaC repo")
	}
	for _, c := range dirty.calls {
		if c[0] == "git" && c[1] == "checkout" {
			t.Error("must not create a branch when the work tree is dirty")
		}
	}

	// An unauthenticated gh must abort too.
	noauth := &fakeRunner{err: map[string]error{"gh auth": errStub}}
	if _, err := OpenPR(context.Background(), noauth, sampleRecs(), Options{RepoDir: t.TempDir()}); err == nil {
		t.Error("expected error when gh is not authenticated")
	}
	for _, c := range noauth.calls {
		if c[0] == "git" && c[1] == "checkout" {
			t.Error("must not create a branch when gh is unauthenticated")
		}
	}
}

var errStub = errStubT("stub error")

type errStubT string

func (e errStubT) Error() string { return string(e) }
