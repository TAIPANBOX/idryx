package enforce

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenPRStopsAtTheFirstFailingStep: every step of the PR flow names
// itself when it fails, and nothing after it runs, so a half-done flow is
// never pushed or opened.
func TestOpenPRStopsAtTheFirstFailingStep(t *testing.T) {
	cases := []struct {
		failKey  string // fakeRunner key of the failing command
		wantErr  string
		mustSkip string // a later command that must not run
	}{
		{"git rev-parse", "is not a git repository", "git checkout"},
		{"git status", "git status:", "git checkout"},
		{"git checkout", "git checkout -b", "git add"},
		{"git add", "git add idryx", "git commit"},
		{"git commit", "git commit:", "git push"},
		{"git push", "git push:", "gh pr"},
		{"gh pr", "gh pr create:", ""},
	}
	for _, c := range cases {
		t.Run(c.failKey, func(t *testing.T) {
			f := &fakeRunner{
				err: map[string]error{c.failKey: errStub},
				out: map[string]string{c.failKey: "tool output for " + c.failKey},
			}
			_, err := OpenPR(context.Background(), f, sampleRecs(), Options{RepoDir: t.TempDir(), Branch: "b"})
			if err == nil {
				t.Fatalf("a failing %s did not fail the flow", c.failKey)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %q, want it to name the step (%q)", err, c.wantErr)
			}
			if !strings.Contains(err.Error(), "tool output for "+c.failKey) {
				t.Errorf("error = %q, want the tool's own output carried", err)
			}
			for _, call := range f.calls {
				if c.mustSkip != "" && strings.Join(call[:2], " ") == c.mustSkip {
					t.Errorf("%s ran after %s failed", c.mustSkip, c.failKey)
				}
			}
		})
	}
}

// TestOpenPRStopsWhenArtifactsCannotBeWritten: the branch exists by then, but
// nothing is staged, committed or pushed.
func TestOpenPRStopsWhenArtifactsCannotBeWritten(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "blocked"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	if _, err := OpenPR(context.Background(), f, sampleRecs(), Options{RepoDir: repo, SubDir: "blocked/sub"}); err == nil {
		t.Fatal("expected an error writing artifacts under a regular file")
	}
	for _, call := range f.calls {
		if call[0] == "git" && (call[1] == "add" || call[1] == "commit" || call[1] == "push") {
			t.Errorf("%v ran after the artifacts failed to write", call)
		}
	}
}

// TestExecRunnerRunsInTheGivenDirectory uses real git: the runner must run
// the command in dir (not the test's own working directory, which is inside
// this repository) and return its combined output.
func TestExecRunnerRunsInTheGivenDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	r := ExecRunner{}
	ctx := context.Background()

	plain := t.TempDir()
	out, err := r.Run(ctx, plain, "git", "rev-parse", "--is-inside-work-tree")
	if err == nil {
		t.Fatalf("rev-parse succeeded in a plain directory %s: %q", plain, out)
	}
	if !strings.Contains(strings.ToLower(out), "not a git repository") {
		t.Errorf("stderr not returned with the error: %q", out)
	}

	repo := t.TempDir()
	if out, err := r.Run(ctx, repo, "git", "init", "-q"); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	out, err = r.Run(ctx, repo, "git", "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		t.Errorf("rev-parse in an initialised repo = %q, %v; want true", out, err)
	}
}
