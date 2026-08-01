# AGENTS.md: working guide for AI agents on idryx

Read this before changing anything. It encodes the conventions that keep idryx
green and consistent. It applies to every package in this repo.

## The non-negotiable gate

CI fails on unformatted code. Run this **before every commit** and fix anything
it reports:

```sh
gofmt -l .                        # MUST print nothing
go vet ./...                      # MUST exit 0
go test ./...                     # all packages MUST be ok
./scripts/detectors-complete.sh   # every detector registered and tested
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

- **`core.fileMode` is `false` in this repository, so git does not record an
  executable bit.** `chmod +x` succeeds on disk, git stores `100644`, and CI
  fails with `Permission denied` on a script that runs fine locally. Add
  executables with `git update-index --chmod=+x <path>`. This bit
  `scripts/detectors-complete.sh` on the commit that introduced it, and it had
  already bitten two other repositories in this estate before that.

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
   a partial graph as complete. *(gate: `scripts/ebpf-optional.sh`, which
   cross-compiles the tree for darwin and windows and requires every path
   through the `!linux` stub to return an error naming the platform)*
5. **A detector that finds nothing must be distinguishable from a detector that
   did not run.** Zero findings is only meaningful next to a case where the
   same detector fires.
   *(test: every detector has its own test file, and the ones sampled assert
   "expected a finding, got none" rather than merely running without panicking;
   several also carry an explicit no-finding case. partly gated:
   `scripts/detectors-complete.sh` holds the structural half, that every
   detector is registered and has a test file at all)*
6. **`sandbox.mod` was meant to prove the core builds without the eBPF
   dependency. It does not, and it is not in this repository.** Measured
   2026-08-01: it is excluded through `.git/info/exclude`, which is per-clone
   and never travels, so no clone has ever had it; and
   `go build -modfile=sandbox.mod ./...` fails on `cilium/ebpf` and on two
   `agent-stack-go` packages. Cross-compilation now proves the same property
   from files that are actually committed. *(not enforced, and its subject does
   not exist. This invariant is a candidate for deletion, see the debt
   section.)*

## Decisions that have no gate yet

**A correction first, because this section was wrong about its own repository.**
It said every invariant was held by prose alone and singled out invariant 5 as
the highest-value untested one. Invariant 5 was already largely held: all 22
detectors have their own test file, and the ones read assert "expected a
finding, got none" through a helper rather than by counting.

The wrong conclusion came from pattern-matching test sources for
`len(alerts) == 0` and believing the count. It missed every helper-based
assertion, which is most of them. **Set a marker from evidence: read the test,
do not match it.**

What is genuinely missing is structural, not behavioural, and it is now
`scripts/detectors-complete.sh`. The registry in `cmd/idryx/main.go` is a
hand-maintained list of 22 constructions. A detector that exists and is never
registered never runs, and it reads as coverage in every review: the file is
there, its tests pass, and no identity graph is ever shown to it. The check
also refuses a registry naming a constructor that does not exist, and a
detector arriving with no test file at all. All three verified by breaking.

Both properties are true today. That is the point: a ratchet against a
regression, not a repair.

**Invariant 4 is now `scripts/ebpf-optional.sh`, and writing it disproved the
plan this section carried.** The plan was to build with `sandbox.mod`. That
turned out to rest on a file that is not in the repository: `sandbox.mod` is
excluded through `.git/info/exclude`, which is a per-clone file that is never
committed and never travels, so nobody who has ever cloned idryx has had it.
It also does not build. `go build -modfile=sandbox.mod ./...` fails on
`cilium/ebpf` and on two `agent-stack-go` packages, so even on the one machine
that has it, it has not been proving anything.

Cross-compiling the whole tree for darwin and windows proves the same property,
from files that are committed, and needs no second module file kept in step by
hand. The gate does that, and separately requires the `!linux` stub in
`cmd/idryx/ebpf_other.go` to name the platform and to return an error on every
path: a stub returning an empty result and no error is the exact failure
invariant 4 exists to prevent, a partial graph presented as complete.

**A decision for the user, not taken here.** Invariant 6 is now describing a
file that does not exist for anyone. My recommendation is to delete it: the
property it wanted is held by cross-compilation, and a second module file
maintained by hand is the same class of drift invariant 3 was written against.
Deleting a numbered invariant is not something a gate-writing pass should do on
its own, so it stays, marked as unheld with its subject missing.

**One thing worth keeping about how this was verified.** Two of the four break
tests were wrong before the check was. The first mutation of the stub failed
the build on unused imports rather than tripping the silent-skip detector, so
it went red for the wrong reason; the second used `golang.org/x/sys/unix` as a
Linux-only import, and it compiles for darwin and windows both. A break test
that goes red proves nothing until you know which line made it red.
**Held by this file alone: invariants 1, 2 and 3.**

- **Invariant 3** is checkable by asserting no local type duplicates a shared
  one, but is only worth writing if a duplicate ever appears.
- Invariants 1 and 2 are judgement and probably stay judgement.

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
