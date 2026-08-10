# AGENTS.md: working guide for AI agents on idryx

Read this before changing anything. It encodes the conventions that keep idryx
green and consistent. It applies to every package in this repo.

## The non-negotiable gate

CI fails on unformatted code. Run this **before every commit** and fix anything
it reports:

```sh
gofmt -l .                        # MUST print nothing
go vet ./...                      # MUST exit 0
go run honnef.co/go/tools/cmd/staticcheck@latest ./...   # MUST exit 0
go test ./...                     # all packages MUST be ok
./scripts/readme-numbers.sh       # every number the README states
./scripts/reproducible-build.sh   # the release asset names (invariant 6)
./scripts/ebpf-optional.sh        # invariant 4, the eBPF layer is optional
./scripts/diagrams-match-detectors.sh  # invariant 8, the pictures count what exists
./scripts/detectors-complete.sh   # every detector registered and tested
./scripts/gates-have-teeth.sh     # invariant 9, the five above can still fail
                                  # (mutates tracked files; needs a clean tree)

# CI runs these in a separate job called `security`, which is exactly why they
# get forgotten: the list above matched the `build` job and stopped there, and
# gosec then refused a branch over an integer conversion that go vet and
# staticcheck both accepted.
go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...   # MUST exit 0
go run golang.org/x/vuln/cmd/govulncheck@latest ./...               # MUST exit 0
```

`make lint` runs the first two; `make test` the tests. CI additionally runs
`go test -race ./...` rather than plain `go test`, and, in separate jobs,
integration tests behind the `integration` build tag against a Postgres
service, plus the eBPF build.

**This list was three commands short until 2026-08-08, and the omission cost
two red CI runs in one day.** It named `gofmt`, `go vet`, `go test` and
`detectors-complete.sh`, while the `build` job runs nine things: staticcheck
and all four scripts were missing from it. One session ran the two scripts this
file named, pushed, and was told by CI that the README badge had drifted; a
later one wrote a `destinations` slice nothing read, which staticcheck catches
and `go vet` does not.

**It happened a third time on 2026-08-09**, after that paragraph was written.
The list was corrected to match the `build` job and stopped there, while gosec
and govulncheck live in a job called `security`. A list covering one job reads
as covering the gate exactly as a list covering half a job does.

The general shape is worth more than any of the three fixes: **an instruction
file that lists some of the gate is trusted for all of it.** If you add a check
to `.github/workflows/ci.yml`, add it here in the same commit, and if you are
about to trust this list, `grep 'run:' .github/workflows/ci.yml` is four seconds
and settles it. It now covers `build` and `security`; `ebpf` and `integration`
need a kernel and a Postgres respectively and are described below instead.

Common trap: editing a Go map/struct literal and leaving it misaligned. Always
`gofmt -w` the files you touch. The most recent human-written detector shipped
unformatted and would have reddened CI, don't repeat it.

## Architecture in one screen

One core, many connectors. Data flows: **source → graph → detectors → output**.

```
cmd/idryx/main.go        CLI: detect | bom | serve | load | remediate | version
internal/model           Identity, Event, Permission, Alert, Severity (the shared types)
internal/ingest          source connectors -> []model.Event OR []model.Identity
internal/ingest/tokenfuse  agent-event NDJSON connector, shared by every bus producer
                           (TokenFuse, Wardryx, Mockryx, Verdryx, scopyx)
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
   name to the `--source` help strings (there are FOUR: detect, bom, serve and
   load each declare their own; keep them identical). This file said three
   until 2026-08-10, which is the same shape as the gate list above: a count in
   an instruction file is trusted and ages separately from what it counts.
   `grep -c 'source: okta' cmd/idryx/main.go` settles it.
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
   a partial graph as complete. Optional means the dependency is genuinely
   absent off Linux, not merely harmless there.
   *(gate: `scripts/ebpf-optional.sh`, which cross-compiles for darwin and
   windows, requires `go list -deps` to contain zero `cilium/ebpf` packages
   there and some on linux, and requires every path through the `!linux` stub
   to return an error naming the platform)*
5. **A detector that finds nothing must be distinguishable from a detector that
   did not run.** Zero findings is only meaningful next to a case where the
   same detector fires.
   *(test: every detector has its own test file, and the ones sampled assert
   "expected a finding, got none" rather than merely running without panicking;
   several also carry an explicit no-finding case. partly gated:
   `scripts/detectors-complete.sh` holds the structural half, that every
   detector is registered and has a test file at all)*
6. **The release asset names carry no version, and that is a contract with
   the outside world rather than a style choice.** it-rat.com links straight to
   `releases/latest/download/<name>`, an address that resolves only while the
   name is stable, so putting a version back into `out=` in `release.yml` turns
   every download link on that site into a 404 at the next tag. Nothing in CI
   would say so; the person who finds out is somebody trying to install this.
   The version is not lost, it moves into the binary, where `-X main.version`
   already puts it and where `idryx version` reads it back. That is the harder of
   the two places to fake: anything between us and a reader can rename a file,
   and nothing between us and a reader can restamp the bytes.
   *(gate: `scripts/reproducible-build.sh`, which reads `out=` out of the
   workflow and refuses if it contains VERSION, and refuses just as loudly if it
   finds no asset name at all, because a check that goes green once its subject
   has vanished is worse than no check. Verified by breaking: putting the version
   back fails it in all four repositories that share this shape.)*

7. **The estate's eBPF network sensor grows here, and nowhere else.** Two
   implementations of one sensor exist: this one (`internal/ebpfcapture`, Go,
   cilium/ebpf) and tokenfuse's `crates/radar` (Rust, aya), which this one was
   ported from. Every capability the sensor gains from now on is built in idryx:
   IPv6, the skipped counters, the cgroup, the kernel timestamp and the
   self-declared identity already are, beaconing shipped on 2026-08-09, and
   corroborating a claim is CLOSED as of 2026-08-10, and closed means two
   detectors and two decisions not to build, which is worth writing out because
   the alternative reading is that somebody forgot.

   `unrouted_egress` checks a claim against an enforcement point's own journal.
   `claimed_agent_unattested` checks it against the Passport's declared binding,
   in the only form a graph can see: an agent the organisation says is bound to
   a workload, whose sole runtime carrier is a process that named itself.

   **Owner and parent are decided against, not deferred.** Owner has no observed
   counterpart at all, so the only available comparison is one declaration
   against another, and `AddIdentity`'s last-non-empty-wins merge erases even
   that before a detector runs. Parent has a counterpart the spec says may
   legitimately differ: SPEC 4.2 is an org chart, SPEC 5 is a per-request chain,
   and this repository's own model doc says they are "usually, but not
   necessarily" the same, so a detector on their inequality cries wolf by
   construction.

   And nothing here makes a claim ATTESTED. That is permanently out of scope at
   this layer, SPEC 3.3, and it is said once here rather than implied.

   **A finding about a claim now leaves this repository, and the form it leaves
   in is a contract rather than a detail.** agent-passport SPEC 3.3 makes
   `claimed:agent://<domain>/<path>` the wire spelling, and the envelope's v0.3
   stamp is what tells a consumer a claim is possible at all. So the sensor's
   on-host convention and the wire form are the same bytes, and
   `internal/events` translates nothing.

   Two rules follow, and both are easy to break by accident. A claimed subject
   is stamped v0.3 and an established one never is: stamping v0.3 on ordinary
   traffic would tell every consumer a claim is possible in a stream where it
   is not. And the trust domain of a claim is never re-stamped with the
   operator's own, because a process writes its own environment and can name
   another organisation's agent; that comparison belongs to the receiver.
   *(test: `TestAClaimedSubjectTravelsUnderItsOwnVersionAndIsCountedApart`)* DNS tunnelling joined JA3/JA4 as
   decided against the same day: both need to read what the application wrote
   into its socket. Radar's role narrows to emitting what
   it observes into the shared agent-event stream; it does not grow new
   observation of its own.
   *(@yurii 2026-08-08, "Idryx основний, radar зводимо до відправника подій")*

   This list named "TLS ClientHello" and "JA3/JA4" until 2026-08-09, when both
   were decided against rather than scheduled (see SECURITY.md). An invariant
   that promises a capability nobody intends to build is the kind of sentence a
   later reader treats as a plan.

   **The port outgrew the original in three measurable places, which is why
   this direction and not the other** (@claude, read off both trees
   2026-08-08). `connect.c` reads the syscall argument through the
   BTF-typed `trace_event_raw_sys_enter` from `vmlinux.h`, so it is CO-RE and
   portable, while radar hard-codes `ctx.read_at::<u64>(24)` with a comment
   saying "offset 24 on x86_64" and will read the wrong bytes on any other
   architecture. `capture_linux.go` skips loopback traffic unless the port is
   11434, 8000 **or 8001**, while radar's filter omits 8001 and drops the
   packet before its own `is_llm` can recognise the local vLLM port it
   nevertheless lists. And this one drops its own traffic by PID, while radar
   compares `comm`, which SECURITY.md correctly says any process can rename.

   The other half of the reason is structural: the eBPF layer here carries
   invariant 4 and `scripts/ebpf-optional.sh`, and radar carries no invariant
   and no test in a repository that has twenty of the former.

   **What this does NOT say.** Radar is not deprecated and its existing
   defects are worth fixing: a sensor that ships and runs should be correct on
   the machine it runs on. The line is between fixing what is there and adding
   what is not.
   *(not enforced. It becomes checkable once radar emits agent-event NDJSON:
   at that point a gate can assert radar's output is the shared envelope
   rather than a terminal table. Until then this paragraph is the whole of
   it, and it should be read as the weakest kind of rule)*

8. **A diagram states no number about this repository that the repository does
   not support.** The pictures are read by more people than the code is, they
   are the first thing on the page, and until 2026-08-08 nothing had ever
   looked at one. `docs/detectors.svg` said "17 deterministic detectors" from
   10 July while the repository grew to 23, and `docs/architecture.svg` said 17
   twice. It was found by somebody redrawing them for an unrelated reason.

   The per-family breakdown is covered for a reason worth keeping: that same
   picture carries "ITDR x4 . NHI x5 . agents/AI x7", which summed to 17 while
   its own headline had just been corrected to 23. One image, two answers, and
   a check on the headline alone goes green over it.

   The PNG is covered for a different reason: the README embeds the PNG, not
   the SVG, so an SVG corrected and never re-rendered leaves the picture a
   reader sees exactly as wrong as before, with every other check passing.
   *(gate: `scripts/diagrams-match-detectors.sh`, which reads the detector
   names from their own `Name()` methods, the families from the README's table,
   every count in `docs/*.svg`, and whether each PNG moved in the same commit
   as its SVG. Verified by breaking it five ways, each of which fails it: a
   stale headline, a stale breakdown with a correct headline, a diagram that
   stops stating a count at all, a new detector with no README row, and an SVG
   committed without its PNG.)*

   **What it deliberately does not do**, so nobody mistakes it for more: it
   never looks at a pixel. A PNG rendered from a stale SVG, at the wrong scale,
   or half-written, passes it cleanly. And it does not read the card contents
   (`excessive_agency . shadow_ai +5 more`), because "+5 more" is relative to
   two names that are themselves a choice, and a script guessing at which
   detector belongs on which card would cry wolf and get switched off.

9. **A check must be able to tell "did not fail" from "did not run", and every
   gate here has been made to fail on purpose to prove it can.** Over 8 and 9
   August 2026 one mistake was made nine times in this repository's tooling and
   never once in its product code. A mutation removed a branch, left an import
   unused, the package stopped compiling, the test never ran, and a grep for
   FAIL read that silence as a pass: three times. A mutation searched for text
   the code did not contain, changed nothing, the tests passed against correct
   code, and the harness announced the test proved nothing, accusing a test that
   worked. A live run printed two "must be 0" lines that were empty rather than
   zero, because they read a field name that does not exist, and empty and zero
   look identical. And in the script written to fix exactly that, twenty lines
   below the fix, two sections printed nothing because a helper taking one
   argument was called with a flag.

   The lesson is not to be careful. Being careful is what failed nine times.
   What survived every one of those oversights was a step carrying an explicit
   comparison and a non-zero exit; what broke every time was a line that only
   printed. So the property is structural: a gate is not finished when it
   passes on correct code, it is finished when somebody has watched it fail on
   the fault it exists for.

   This also puts a check under a claim invariant 6 has made since it was
   written, that `reproducible-build.sh` refuses just as loudly when it finds
   no asset name at all. That was true, and nothing had ever confirmed it.
   *(gate: `scripts/gates-have-teeth.sh`, 13 cases over all five gates: six
   real faults each must catch, two non-faults they must not, and five subjects
   taken away entirely, where the gate must say it measured nothing instead of
   reporting OK. Every mutation asserts it applied, because a mutation that
   changed no file is the second failure above, and this harness must not
   commit the error it exists to catch.)*

   **What it does not cover.** It cannot test itself; nothing watches this one
   fail. It proves each gate catches the faults named in it, not every fault of
   that kind. And writing it found no hole in any of the five, which is the
   result to expect from a ratchet: it is here so the next change to a gate
   cannot quietly remove its teeth, not because they were missing.

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

**Invariant 6 is gone, and `sandbox.mod` with it** (@yurii 2026-08-01, "go").
It said sandbox.mod "exists to prove the core builds without the eBPF
dependency" and "is not a scratch file". All three claims were false: it was
never in the repository, it did not build, and it also excluded
`agent-stack-go`, which invariant 3 says is the ONLY source of the wire types
and therefore never optional. It was measuring the wrong boundary, from a file
nobody had.

**The property it wanted was real, and it now holds for the first time.** Until
2026-08-01 the tree cross-compiled for windows while dragging all 19
`cilium/ebpf` packages into a build that can never use them, because bpf2go
tags its output by ARCHITECTURE with no OS constraint and has no flag to add
one. Putting `linux &&` in front of those two tags takes darwin and windows
from 19 packages to zero, with linux unchanged. That is the supply-chain claim
"the eBPF layer is optional" actually being true rather than merely sounding
true, and part 2 of the gate now holds it.

**One visible debt, chosen over an invisible one.** Those two files are
bpf2go output marked `DO NOT EDIT`, so a regeneration removes the `linux &&`
silently. The gate fails on the next push when it does, and a note beside the
`//go:generate` line in `capture_linux.go` says to put it back. A wart that
trips a check beats a correctness property nobody is watching.

**One thing worth keeping about how this was verified.** Two of the four break
tests were wrong before the check was. The first mutation of the stub failed
the build on unused imports rather than tripping the silent-skip detector, so
it went red for the wrong reason; the second used `golang.org/x/sys/unix` as a
Linux-only import, and it compiles for darwin and windows both. A break test
that goes red proves nothing until you know which line made it red.
**Held by this file alone: invariants 1, 2, 3 and 7.**

- **Invariant 3** is checkable by asserting no local type duplicates a shared
  one, but is only worth writing if a duplicate ever appears.
- Invariants 1 and 2 are judgement and probably stay judgement.
- **Invariant 7** is prose today and has a known point at which it stops being
  prose: the moment radar emits agent-event NDJSON, a check can require that
  shape and refuse a terminal-table build. Written down here rather than left
  as an intention, because a rule about where work happens is exactly the kind
  nobody notices breaking: the next capability added in the wrong repository
  compiles, passes its own CI, and reads as progress.

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
