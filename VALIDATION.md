# Live infrastructure validation

Idryx was run against a real Postgres 16 backend and real agent-fleet event data on disposable Hetzner
infrastructure before any public launch - closing the gap between its (previously fixture-only) storage
layer and a real database under real migrations.

## Real-Postgres validation

- **16/16 integration tests pass** against a real Postgres 16 instance (previously only exercised
  against fixtures).
- The delegation-chain backfill migration (a `DO $$` PL/pgSQL block) is **correct and idempotent**
  across repeated runs.
- A full CLI round-trip - TokenFuse agent-event NDJSON + Agent Passport records → Postgres → detectors
  reading back - correctly fired `runaway_agent`, `attestation_missing`, and `orphaned_nhi` off
  Postgres-backed state, not just an in-memory fixture.
- No real-Postgres-specific bug found. One operational note (not a bug): event ingestion has no dedup
  key, so replaying the same NDJSON file doubles events - dedupe upstream or truncate between runs.

Re-confirmed in a later cross-machine run: all packages green against a separately-provisioned real
Postgres 16, and again in an enriched multi-agent campaign - the run pictured in the dashboard referenced
from the README: 6 non-human identities tracked (`scraper`, `orchestrator`, `support`, `analyst`,
`billing`, `looper`), 3 detectors fired live (`runaway_agent` HIGH on the scraper's breaker trips and
missing attestation, `bom_incomplete` MEDIUM, `orphaned_nhi` LOW on one unmapped identity), and a
CycloneDX 1.6 Agent-BOM generated end to end - all backed by the same real Postgres 16.

## What this proves

- The detector suite (`runaway_agent`, `attestation_missing`, `bom_incomplete`, `orphaned_nhi`, and
  others) fires correctly off real database state across multiple runs, not just fixtures.
- The delegation-chain backfill migration is production-safe to re-run.
- Agent-BOM generation (CycloneDX 1.6) works end to end against a real Postgres-backed event history.

## A thousand agents, and the ranking that did not survive them

2026-08-04, on a three-node k3s cluster in AWS. `idryx serve` read the TokenFuse event stream live
(`--load tokenfuse:/var/lib/stack/events/tokenfuse.ndjson`) while fleets of real agents ran real
calls against the real Anthropic API. **999 unique agent identities, 3000 alerts, unattended.**

The computation held. The ranking did not, and that is the finding.

| Detector | Alerts |
|---|---|
| `runaway_agent` | 1000 |
| `bom_incomplete` | 1000 |
| `orphaned_nhi` | 1000 |

Exactly one thousand of each: **every agent tripped all three**. Inside `runaway_agent` the breaker
counts behind those alerts ran from **1 (minimum) to 2 (median) to 73 (worst)**, a
twenty-nine-fold spread. **All 1000 alerts carried the identical severity, `medium`.** The number
an operator needed was printed in the summary string and absent from the field they sort by.

The cause was in the design and not in a bug: severity escalated only on corroborating context
(privilege, delegation depth, attestation, blast radius), and in a real fleet most agents have
none of it. At the six identities in the README demo this is invisible. At a thousand it is a list
nobody can work in.

Fixed by letting the size of the incident raise the verdict on its own beside the context rules:
ten incidents inside the window is at least `high`, fifty is `critical`. Against the measured
distribution that turns 1000 identical `medium` rows into **1 critical, 4 high and 995 medium**.
Thresholds are fixed rather than fleet-relative on purpose: a relative threshold reads well until
every agent is misbehaving, and then it calls the worst offenders normal. Determinism is
invariant 1.

**What this run did not establish.** Three detectors of twenty-two. The other nineteen had no
occasion to fire in this data, so nothing here is said about their behaviour at scale.

## Method

Disposable Hetzner VPS boxes (deleted after each run) with a real Postgres 16 instance; code delivered
as a `git archive` tarball (no secrets, no `.git`, no token); every service bound to `127.0.0.1` only,
reached exclusively via SSH tunnel. Nothing from these runs was ever exposed publicly, and no
infrastructure or secret from the campaign persists today.

## The dashboard escaped an identity ID for the wrong parser

2026-08-05, from a read-only audit of the source rather than a run. Every row of the identity list
carried its own click handler, `onclick="selectIdentity('<id>')"`, and the ID went in through `esc()`,
the HTML entity escaper, at `internal/server/dashboard.go:834`. The other two handlers in the same
file, the Copy Terraform button and the identity link in the alert table, already used `escJS()`, the
helper written for exactly this context. One site of three was missed.

`esc()` turns `'` into `&#39;`, and an HTML parser decodes that back into an apostrophe **before** the
JS parser ever reads the handler. Running the page's own two escapers over an ingested ID of
`agent:x');document.title='pwned';//` shows what each parser gets (@measured `node`, both functions
read out of `dashboard.go` rather than retyped, 2026-08-05):

```
esc    attribute source   : selectIdentity('agent:x&#39;);document.title=&#39;pwned&#39;;//')
esc    JS the parser sees : selectIdentity('agent:x');document.title='pwned';//')
escJS  JS the parser sees : selectIdentity('agent\x3ax\x27\x29\x3bdocument\x2etitle\x3d\x27pwned...')
```

The literal closes after `agent:x` and the rest is statements. Identity IDs arrive verbatim from
ingested inventory and IAM data, which SECURITY.md invariant 3 classes as attacker-influenced, so this
is stored XSS in a dashboard whose whole job is to be pointed at a hostile fleet. The same line was
also a quiet functional bug: an ID containing `&`, `<`, `"` or `'` reached `selectIdentity()`
entity-encoded, matched nothing in `globalIdentities`, and opened no detail panel.

**The regression test was there and could not fail.** It asserted that the served HTML embeds no
identity data (true, and unrelated: the escaping happens in the browser) and that the string
`function escJS` appears somewhere on the page (true while nothing called it). Both passed against the
broken line for as long as it existed. It now asserts the property instead: in the page as served,
every value spliced into an event-handler attribute goes through `escJS`, and a page with no
interpolated handler at all fails rather than passes. Red on the unfixed line, green after
(@measured `go test ./internal/server -run TestEventHandlerAttributesEscapeForJSContext`, 2026-08-05).

**What this did not establish.** The payload was not fired in a real browser; the evidence above is at
the escaping layer, one decode short of a click. And the check reads the shipped page's own syntax, so
it holds this shape of handler, not a future one built by `addEventListener` or a template literal.

## `idryx serve` defaulted to every interface, not just loopback

2026-08-05, from the same read-only audit. `idryx serve`'s `-addr` flag defaulted to `:8080`
(`cmd/idryx/main.go`, `runServe`), which `net/http` binds to every interface, not just loopback.
`internal/server/server.go` serves `/api/alerts`, `/api/identities` and `/api/remediations` with no
authentication, authorization, CORS policy or rate limiting -- together the whole identity graph,
every alert summary and every generated remediation. SECURITY.md documents that gap deliberately, on
the assumption the operator reaches the dashboard over a WireGuard/SSH tunnel: a documented
constraint, not a defect. The defect was the *default bind*, which made that constraint easy to
violate by accident -- `idryx serve <log.json>` with no other flags put an identity plane on the
open network.

The regression test asserts the default address is loopback directly, with no listener and no
network call, because the property under test is a compile-time constant: `defaultServeAddr =
"127.0.0.1:8080"`, checked with the same `isLoopbackHost` helper the runtime warning below uses.
Before the fix, this did not compile, because the code had no way to express "the default is
loopback" at all (@measured `go test ./cmd/idryx/... -run TestServeDefaultAddrIsLoopback`,
2026-08-05, against the unfixed tree):

```
cmd/idryx/main_test.go:452:36: undefined: defaultServeAddr
cmd/idryx/main_test.go:456:6: undefined: isLoopbackHost
FAIL	github.com/TAIPANBOX/idryx/cmd/idryx [build failed]
```

Fixed by defaulting `-addr` to `127.0.0.1:8080`. An operator who wants a wider bind still gets one by
passing `-addr` explicitly, and now sees why it matters: mirroring the precedent already in this
estate (tokenfuse's control plane, `TOKENFUSE_CLOUD_HOST`, `crates/cloud/src/main.rs`, binds to
loopback by default and warns loudly on a wider bind), a non-loopback `-addr` now prints an
unmissable stderr warning naming the exact SECURITY.md gap it is exposing.

**What this did not establish.** No live network scan of a bound socket. The evidence is that the
default *value* is loopback and that the warning fires on the right set of addresses (@measured `go
test ./cmd/idryx/... -run 'TestIsLoopbackHost|TestWarnIfNonLoopback'`, 2026-08-05, all pass), not
that `net/http.ListenAndServe` refuses external connections on `127.0.0.1` -- that is `net/http` and
the kernel's own well-established behavior, not something this change touches.

## Four connectors dropped malformed records with no counter and no report

2026-08-05, from the same read-only audit. `internal/ingest/okta.go`, `entra.go`, `cloudtrail.go`
and `egress.go` each `continue`d past any record whose timestamp did not parse as RFC3339, and
nothing anywhere surfaced how many were skipped. For an identity plane, a silently truncated Okta
log is a detection gap nobody can see.

The pattern to fix it already existed in this repo: `internal/ingest/tokenfuse/tokenfuse.go`
carries a `Report{Lines, Malformed, UnknownTypes}` and `cmd/idryx/main.go` prints a stderr summary
from it. The same shape now applies here, as a new `ingest.Report{Records, Malformed}` (no
`UnknownTypes`: these four have no notion of an unrecognized *type*, only an unparseable
timestamp), and a new `reportIngest` in `cmd/idryx/main.go` prints the same stderr summary shape
`reportTokenFuse`/`reportPassports` already established, rather than a second mechanism.

Before the fix this had no way to compile: every new test asserting `rep.Malformed` against
`Okta`/`Entra`/`CloudTrail`/`Egress`/`Agents` failed to build, because none of the five returned
anything but two values (@measured `go test ./internal/ingest/... ./internal/detect/...`,
2026-08-05, against the unfixed tree):

```
internal/ingest/agents_test.go:19:17: assignment mismatch: 3 variables but Agents returns 2 values
internal/ingest/egress_test.go:18:22: assignment mismatch: 3 variables but Egress returns 2 values
internal/ingest/ingest_test.go:20:22: assignment mismatch: 3 variables but Entra returns 2 values
internal/ingest/ingest_test.go:179:22: assignment mismatch: 3 variables but CloudTrail returns 2 values
internal/ingest/okta_test.go:21:22: assignment mismatch: 3 variables but Okta returns 2 values
FAIL	github.com/TAIPANBOX/idryx/internal/ingest [build failed]
internal/detect/detect_test.go:19:20: assignment mismatch: 3 variables but ingest.Okta returns 2 values
FAIL	github.com/TAIPANBOX/idryx/internal/detect [build failed]
```

`cmd/idryx/main.go`'s own wiring (the new `reportIngest`, and its two call sites inside `populate`)
was verified the same way rather than assumed: temporarily stubbing `reportIngest` to a no-op, and
separately dropping its two call sites, reproduced the identical failure mode against
otherwise-fixed connectors (@measured `go test ./cmd/idryx/... -run
'TestReportIngestStderrSummary|TestPopulateSurfacesMalformedRecordsOnStderr'`, 2026-08-05: both
`FAIL`, `expected ... got ""`), then passed once restored.

**Folded in, on inspection: `internal/ingest/agents.go`'s "created" field.** A non-empty `created`
that fails to parse as RFC3339 was silently absorbed into a zero `Created` -- the same outcome as
never supplying it -- which makes `GenerateRotation` treat the agent as nothing-to-rotate and
`stale_nhi` skip it entirely: a typo in an agent inventory silently removes that agent from two
checks. Unlike the four event connectors this does not drop the record (the agent is still
ingested; only the one field defaults), so it gets its own test shape rather than reusing the
four connectors' "one malformed row is missing from the output" assertion, but it reuses the
identical `Report` type and reaches `reportIngest` through the same `parseInventory` dispatch every
other inventory source already goes through: `aws_iam`/`gcp_iam`/`azure`/`mcp` now return that same
signature shape too, always with the zero `Report`, so nothing about their own behavior changes.

**What this did not establish.** No malformed record from a real IdP or CloudTrail export, only
hand-built fixtures with one bad row each. `runLoad`'s own two `reportIngest` call sites (the `idryx
load --db` path) are exercised by compilation and by being structurally identical to `populate`'s --
same `parseSource`/`parseInventory` dispatch, same `reportIngest` call -- but not by a dedicated
test, because `runLoad` requires a real Postgres DSN and standing one up was out of scope for this
fix.
