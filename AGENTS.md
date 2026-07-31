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
internal/sink            Slack + generic webhook + OTLP delivery
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

## Hard invariants

Each one carries how it is held today. Use `(gate: ...)`, `(test: ...)`,
`(partly gated: ...)` or `(not enforced)`, and use the weakest one that is
true. An invariant with no check, written as though it had one, is worse than
an absent invariant.

1. **Detection is deterministic.** A detector answers from the graph it was
   given. Same graph in, same findings out, in the same order. An identity
   finding that cannot be reproduced from the same input is not evidence and
   cannot survive being questioned. *(not enforced)*
2. **Idryx observes, it does not act on the identities it finds.** Remediation
   produces a proposal a human applies, never an automatic revoke, disable, or
   permission change against a live directory. This boundary is the difference
   between an identity-security tool and an attack tool. *(not enforced)*
3. **`agent-stack-go` is the only source of the wire types.** Passport, event
   and chain types come from the shared module, pinned by tag. The old
   `internal/` equivalents are exactly the drift this module was created to
   end; do not reintroduce one. *(not enforced)*
4. **The eBPF layer is optional and Linux-only, and its absence is a reported
   fact, not a silent skip.** Idryx must run and produce a graph on a machine
   with no eBPF, and must say what it could not observe rather than presenting
   a partial graph as complete. *(not enforced)*
5. **A detector that finds nothing must be distinguishable from a detector that
   did not run.** Zero findings is only meaningful next to a case where the
   same detector fires. Every new detector needs a fixture that makes it
   report. *(not enforced)*
6. **`sandbox.mod` exists to prove the core builds without the eBPF
   dependency.** It is not a scratch file. Keep it in step with `go.mod` for
   the dependencies it does declare. *(not enforced)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.
**Every invariant above is held by this file alone.** That is the honest state.

Two of them are mechanically checkable and are the place to start:

- **Invariant 4** is the cheapest: build with `sandbox.mod` and assert the
  binary runs and reports the missing capability, rather than assuming it.
- **Invariant 5** is the highest value, and it is the same class as "zero
  violations is worth exactly as much as the ability to see one". A test that
  runs every registered detector against a fixture designed to trip it, and
  fails if any detector reports clean, turns a whole class of silent
  regressions into a red build.

Invariant 3 is checkable by asserting no local type duplicates a shared one,
but is only worth writing if a duplicate ever appears. Invariants 1 and 2 are
judgement and probably stay judgement.

## Standing rule

An approved architecture decision is **not finished** until it is two things: a
numbered invariant in this file, and a gate in a script or a test if it can be
checked structurally. Until then it is a document, and documents do not stop
code.

When the user approves a decision, add it here in the same session. Do not
defer it, because later is where the drift lives.

## Scope

This repo is **idryx** only. Do not touch the sibling `Qryx` project or its GitHub
repo unless explicitly asked.

**One instruction file.** This is it. `CLAUDE.md` in this repo is a pointer to
this file and holds no content of its own, deliberately: two instruction files
in one repo are two copies of one thing, and two copies of one thing always
diverge. If you add guidance, add it here.
