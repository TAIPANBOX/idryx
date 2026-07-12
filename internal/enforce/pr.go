// Package enforce turns remediation recommendations into a GitHub pull request
// against an infrastructure-as-code repository. idryx never applies the change:
// the PR is the proposal, and apply stays with the reviewer and CI. This keeps
// idryx read-only against the cloud and IdP while still delivering remediation
// through the standard GitOps channel.
package enforce

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// Runner executes an external command in a working directory and returns its
// combined output. It is the seam that lets tests verify the git/gh sequence
// without invoking real binaries.
type Runner interface {
	Run(ctx context.Context, dir, name string, args ...string) (string, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run executes name+args in dir and returns combined stdout+stderr.
func (ExecRunner) Run(ctx context.Context, dir, name string, args ...string) (string, error) {
	// name/args are internally constructed (git/gh invocations), not user-derived, and run without a shell
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// nowFunc is the clock; tests override it for a deterministic branch name.
var nowFunc = time.Now

// Options configures the pull request.
type Options struct {
	RepoDir string // path to the IaC git working tree (required)
	SubDir  string // directory within the repo for artifacts (default "idryx")
	Base    string // base branch for the PR (default "main")
	Branch  string // head branch name (default idryx/remediation-<unix>)
	Title   string // PR title (default generated)
	Body    string // PR body (default generated from the recommendations)
}

// OpenPR writes the remediation artifacts into the repo, commits them on a new
// branch, pushes, and opens a GitHub pull request via gh. It returns the PR URL
// printed by gh. idryx does not apply the change — the PR is the proposal.
func OpenPR(ctx context.Context, r Runner, recs []*remediation.Recommendation, opts Options) (string, error) {
	if len(recs) == 0 {
		return "", fmt.Errorf("no remediations to open a PR for")
	}
	if opts.RepoDir == "" {
		return "", fmt.Errorf("RepoDir is required")
	}
	subDir := opts.SubDir
	if subDir == "" {
		subDir = "idryx"
	}
	base := opts.Base
	if base == "" {
		base = "main"
	}
	branch := opts.Branch
	if branch == "" {
		branch = fmt.Sprintf("idryx/remediation-%d", nowFunc().Unix())
	}
	title := opts.Title
	if title == "" {
		title = fmt.Sprintf("idryx: least-privilege & rotation remediations (%d)", len(recs))
	}
	body := opts.Body
	if body == "" {
		body = defaultBody(recs)
	}

	// 0. Preflight: fail before touching the repo if the environment can't
	// complete the flow, so we never leave a half-created branch behind.
	if err := preflight(ctx, r, opts.RepoDir); err != nil {
		return "", err
	}

	// 1. Create the branch off the current HEAD.
	if out, err := r.Run(ctx, opts.RepoDir, "git", "checkout", "-b", branch); err != nil {
		return "", fmt.Errorf("git checkout -b %s: %w\n%s", branch, err, out)
	}

	// 2. Write artifacts into <repo>/<subDir> (single source of truth with --out).
	if _, err := remediation.WriteArtifacts(filepath.Join(opts.RepoDir, subDir), recs); err != nil {
		return "", err
	}

	// 3. Stage, commit, push the branch.
	if out, err := r.Run(ctx, opts.RepoDir, "git", "add", subDir); err != nil {
		return "", fmt.Errorf("git add %s: %w\n%s", subDir, err, out)
	}
	if out, err := r.Run(ctx, opts.RepoDir, "git", "commit", "-m", title); err != nil {
		return "", fmt.Errorf("git commit: %w\n%s", err, out)
	}
	if out, err := r.Run(ctx, opts.RepoDir, "git", "push", "-u", "origin", branch); err != nil {
		return "", fmt.Errorf("git push: %w\n%s", err, out)
	}

	// 4. Open the PR with gh; its stdout is the PR URL.
	out, err := r.Run(ctx, opts.RepoDir, "gh", "pr", "create",
		"--base", base, "--head", branch, "--title", title, "--body", body)
	if err != nil {
		return "", fmt.Errorf("gh pr create: %w\n%s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// preflight verifies the environment can complete the PR flow before any
// mutation: the path is a git work tree, that tree is clean (so idryx's commit
// contains only its own artifacts), and gh is authenticated. Any failure aborts
// before the branch is created.
func preflight(ctx context.Context, r Runner, repoDir string) error {
	if out, err := r.Run(ctx, repoDir, "git", "rev-parse", "--is-inside-work-tree"); err != nil {
		return fmt.Errorf("%s is not a git repository: %w\n%s", repoDir, err, out)
	}
	out, err := r.Run(ctx, repoDir, "git", "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("git status: %w\n%s", err, out)
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("the IaC repo at %s has uncommitted changes; commit or stash them first so the remediation PR contains only idryx's artifacts", repoDir)
	}
	if out, err := r.Run(ctx, repoDir, "gh", "auth", "status"); err != nil {
		return fmt.Errorf("gh is not authenticated (run `gh auth login`): %w\n%s", err, out)
	}
	return nil
}

// defaultBody renders a review-oriented PR description that states idryx's
// read-only stance and lists every proposed remediation.
func defaultBody(recs []*remediation.Recommendation) string {
	var sb strings.Builder
	sb.WriteString("Automated least-privilege and credential-rotation remediations proposed by idryx.\n\n")
	sb.WriteString("idryx is read-only against your cloud and IdP — this PR is a proposal. ")
	sb.WriteString("The files under the artifacts directory are human-readable proposed diffs, not drop-in Terraform: review each one, fold the change into your own configuration, and apply through your normal plan/apply workflow.\n\n")
	for _, rem := range recs {
		fmt.Fprintf(&sb, "- **%s** (`%s`): %s\n", rem.IdentityID, rem.Kind, rem.Explanation)
	}
	return sb.String()
}
