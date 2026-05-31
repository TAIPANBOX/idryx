# Security Policy

idryx is a security product, so its own trust boundaries matter. This document
states the threat model, the design invariants that bound idryx's blast radius,
and how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately, not in public issues or PRs:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/idryx/security/advisories/new>

Include the affected version/commit, a description, and a minimal reproduction.
We aim to acknowledge within a few days and to fix high-severity issues before
any public disclosure. There is no bug-bounty program; we credit reporters in the
advisory unless you prefer otherwise.

## Design invariants

These are load-bearing security properties. A change that breaks one is a bug.

1. **Read-only against the cloud and IdP.** idryx observes; it never mutates the
   IdP, cloud provider, or any monitored system. Remediation is delivered as
   Terraform artifacts and (optionally) a pull request — never `terraform apply`.
   Apply stays with the operator and their CI.
2. **Detection is deterministic.** Detectors are statistics and rules over the
   graph. No LLM is ever in the detection path; LLMs may only ever be an
   interface layer (NL queries, explanations).
3. **Inputs are untrusted.** Every connector input — IdP logs, IAM dumps, agent
   and MCP inventories, egress logs — is attacker-influenced data. Fields that
   flow to a sink (a filename, a shell/`gh` argument, HTML/JS, SQL) must be
   neutralised for that sink's context.

## Threat model

### Trust boundaries

| Boundary | Untrusted side | Defense |
| --- | --- | --- |
| Connector ingest | log/inventory JSON (identity IDs, policy names, hosts) | parsed into a typed model; never `eval`'d or shelled |
| Dashboard (`serve`) | identity IDs etc. rendered into HTML/JS | client-rendered from JSON APIs; `esc()` for HTML, `escJS()` for JS-string-in-attribute contexts |
| JSON API | same fields returned to clients | `encoding/json` (data, not markup) |
| Remediation artifacts (`--out`, `--open-pr`) | identity IDs used as filenames | `SanitizeName` whitelists `[A-Za-z0-9._-]`; collisions de-duplicated; no path traversal |
| Enforcement (`--open-pr`) | identity/policy names as `git`/`gh` arguments | executed via `exec.CommandContext` with an argument slice — **no shell**, so no command injection; a preflight verifies a clean git work tree and authenticated `gh` before any branch is created |
| Postgres (`--db`, `--save-db`) | event/identity/remediation rows | parameterized queries only (pgx); no string-concatenated SQL |

### What idryx deliberately does NOT defend against

- **The contents of generated Terraform.** Remediation `.tf` is a proposal for a
  human to review and apply through their own plan/apply workflow. idryx does not
  execute it; an operator who applies unreviewed generated IaC owns that risk.
- **Credentials and access for the connectors themselves.** idryx reads whatever
  logs/inventory you feed it; securing those exports and any cloud read
  credentials is the operator's responsibility.
- **The Postgres instance.** idryx uses the DSN you provide; database access
  control and network exposure are out of scope.
- **`idryx serve` as a public endpoint.** The dashboard is read-only and has no
  authentication; run it behind your own auth/network controls, not on the open
  internet.

## Supported versions

idryx is pre-1.0; only `main` is supported. Fixes land on `main` and are not
backported.

## Verifying a build

Every change must pass the full gate before merge: `gofmt -l .` clean,
`go vet ./...`, `staticcheck ./...` (zero findings), and `go test ./...`. CI also
runs `go test -race` and the Postgres-backed integration tests. See
[`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
