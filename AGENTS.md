# AGENTS.md: working guide for AI agents on idryx

Read this before changing anything. It encodes the conventions that keep idryx
green and consistent. It applies to every package in this repo.

## The non-negotiable gate

CI fails on unformatted code. Run this **before every commit** and fix anything
it reports:

```sh
gofmt -l .            # MUST print nothing
go vet ./...          # MUST exit 0
go test ./...         # all packages MUST be ok
```

`make lint` runs the first two; `make test` the third. CI additionally runs
`go test -race ./...` and, in a separate job, integration tests behind the
`integration` build tag against a Postgres service.

Common trap: editing a Go map/struct literal and leaving it misaligned. Always
`gofmt -w` the files you touch. The most recent human-written detector shipped
unformatted and would have reddened CI, don't repeat it.

## Architecture in one screen

One core, many connectors. Data flows: **source → graph → detectors → output**.

```
cmd/idryx/main.go        CLI: detect | bom | serve | load | remediate | version
internal/model           Identity, Event, Permission, Alert, Severity (the shared types)
internal/ingest          source connectors -> []model.Event OR []model.Identity
internal/ingest/tokenfuse  TokenFuse/Wardryx/Mockryx/Verdryx agent-event NDJSON connector
internal/ingest/passport   Agent Passport JSON ingestion
internal/graph           Store (in-memory) + PgStore (Postgres); both satisfy graph.Reader
internal/baseline        per-identity behavioral baseline (Build / NewProfile+Observe / Score)
internal/detect          Detector interface
internal/detect/detectors  the concrete detectors
internal/bom             CycloneDX Agent-BOM builder
internal/remediation     right-sizing + credential-rotation Terraform generation
internal/enforce         opens a GitHub PR from remediation output (git + gh)
internal/report          human + JSON alert rendering
internal/sink            Slack + generic webhook delivery
internal/server          read-only HTTP dashboard + JSON API
```

Hard rules:
- **Detection is deterministic** (statistics + rules over the graph). Never put an
  LLM in the detection path, LLMs are only ever an interface layer.
- **Read-only.** idryx observes; it never mutates the IdP/cloud.
- Detectors depend on `graph.Reader`, never on the concrete `*graph.Store`, so the
  Postgres backend works unchanged.

## Recipe: add a detector

1. Create `internal/detect/detectors/<name>.go`. Implement:
   ```go
   type Detector interface {
       Name() string
       Detect(g graph.Reader) []model.Alert
   }
   ```
2. Iterate `g.Identities()`; each `*model.Identity` carries `Events`, `Permissions`,
   `Type`, `Owner`, `OnBehalfOf`, etc. Use the helpers: `id.IsNHI()`, `id.IsAgent()`,
   `id.HasAdmin()`.
3. For time, call the package-level `now()` (in `util.go`/detectors), never
   `time.Now()` directly, so tests can pin the clock with `withFixedNow(t)`.
4. Skip identity kinds you don't target (e.g. NHI detectors `continue` on humans).
5. Register it in `runDetectors` in `cmd/idryx/main.go`. **A detector that isn't
   registered does nothing**, this is the most common omission.
6. Add `<name>_test.go` using the shared `detect(d, g)` helper and `withFixedNow(t)`;
   assert both positive and negative cases (the wrong identity kind must NOT fire).
7. Document it under the right family in `README.md` and the Detectors diagram text.

## Recipe: add a source connector

Sources are two kinds:
- **Event sources** (logs): parse to `[]model.Event`, wire into `parseSource` in
  `main.go`. Examples: `okta`, `entra`, `cloudtrail`, `egress`.
- **Inventory sources** (identities + permissions): parse to `[]model.Identity`,
  wire into `parseInventory` in `main.go`. Examples: `aws_iam`, `gcp_iam`, `azure`,
  `agents`.

Steps:
1. `internal/ingest/<source>.go` with a `func <Source>(data []byte) (...)`.
2. Normalize vendor fields into the shared model, do not leak vendor shapes past
   the connector.
3. Wire into `parseSource` **or** `parseInventory` (not both), and add the source
   name to the `--source` help strings (there are three; keep them identical).
4. Add `<source>_test.go` and a fixture under `testdata/`. Update the connectors
   table in `README.md` and the `make nhi`/`make detect` target if relevant.

## Commit & push workflow

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit; small and focused.
- End every commit body with:
  `Co-Authored-By: Claude <noreply@anthropic.com>`
- Never `--no-verify`, never force-push.
- After committing, push to `origin main` and confirm `HEAD == origin/main`.
- Everything in GitHub is **English** and the repo is **public**.

## Known false signals

- The editor's LSP sometimes reports stale `InvalidIfaceAssign` errors on
  `cmd/idryx/main.go` (detectors "don't implement detect.Detector"). If
  `go build ./...` succeeds, these are **stale cache**, ignore them.
- `Edit` can fail with "String to replace not found" right after a linter touches a
  file. Re-`Read` the file and retry against the current text.

## Scope

This repo is **idryx** only. Do not touch the sibling `Qryx` project or its GitHub
repo unless explicitly asked.
