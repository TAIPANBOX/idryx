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

## Alert delivery failure did not fail the command

2026-08-05, from the same read-only audit. `runDetect` in `cmd/idryx/main.go` looped over the
constructed sinks and, on a `Send` error, printed one stderr line and continued -- but the function
then unconditionally `return nil`. A cron or CI invocation whose SIEM webhook is 401ing, or whose
Slack URL is dead, reported success indefinitely: exit 0 either way.

Fixed by counting delivery failures across the loop (which already tried every sink; nothing here
changes that) and returning a wrapped `errSinkDelivery` when any sink failed, which `main()` maps to
exit code 3 -- distinct from exit 1 (idryx's existing generic error path: bad flags, an unreadable
file, a graph that failed to build) and from exit 0 (a clean run). 3, not 2: tokenfuse's own
`mcp-scan` command (`crates/gateway/src/main.rs`) uses 1 for "findings met `--fail-on`'s threshold"
and 2 for "a bad `--fail-on` value". idryx has no `--fail-on` flag today -- that premise, checked
against this repository rather than assumed from tokenfuse's, does not hold here -- but if idryx ever
grows one shaped like tokenfuse's, this choice leaves both of tokenfuse's codes free for it to reuse
verbatim, rather than a sink-delivery failure quietly squatting on either meaning first.

The regression tests cover the failing case, the working case, and the partial case named
explicitly: two sinks, one fails. The failure must still be visible AND the working sink must still
receive the alerts, proving the loop was never short-circuited. Before the fix none of this
compiled, because neither `errSinkDelivery` nor `exitSinkDelivery` existed (@measured `go vet
./cmd/idryx/...`, 2026-08-05, against the unfixed tree):

```
cmd/idryx/main_test.go:643:21: undefined: errSinkDelivery
cmd/idryx/main_test.go:698:21: undefined: errSinkDelivery
cmd/idryx/main_test.go:763:41: undefined: exitSinkDelivery
cmd/idryx/main_test.go:764:77: undefined: exitSinkDelivery
FAIL	github.com/TAIPANBOX/idryx/cmd/idryx [build failed]
```

Two of the five new tests exec the built binary rather than calling `run()`/`runDetect()`
in-process (@measured `go test ./cmd/idryx/... -run
'TestMainExitCodeSinkDeliveryFailure|TestMainExitCodeCleanRunIsZero'`, 2026-08-05, both pass),
because `main()`'s own `os.Exit` mapping is the one piece of this fix an in-process test cannot
reach: `os.Exit` inside the test binary would kill the test run itself, so a bug where `main()`
forgot to check `errors.Is(err, errSinkDelivery)` at all would pass every in-process assertion and
still exit 0 for a real caller.

**What this did not establish.** No real SIEM/Slack endpoint; the failing sinks in every test are
local `httptest` servers returning 401/500. And OTLP (`internal/sink/otlp.go`) was exercised only
through the same shared loop in `runDetect`, via Slack/webhook mocks -- its own `Send` was not
separately driven into a failure to confirm this specific loop counts an OTLP failure identically,
though the loop's logic is sink-agnostic (it only calls the `sink.Sink` interface, the same one
Slack and webhook implement).

<<<<<<< HEAD
## Ingesting one inventory twice doubled every permission

2026-08-06, from a read-only audit of the source. `graph.Store.AddIdentity`
(`internal/graph/store.go`) ended on `id.Permissions = append(id.Permissions, in.Permissions...)`,
an unconditional append, so the same inventory merged into one in-memory graph twice came back
carrying every grant twice. Every other field in that same function already merged rather than
accumulated: `Privileged` ORs, `Source`/`Owner`/`Runtime`/`Attestation` overwrite only when the
incoming value is non-empty, `LastUsed` keeps the later of the two. Permissions were the one field
that grew.

The rule was already written down twice in this repository, and held in both other places.
`AddEvent`, ten lines above in the same file, dedupes on the event's natural key and says why:
replaying a source file "cannot double-count events and inflate threshold detectors like
mfa_fatigue". The Postgres backend never had the bug either, from `UNIQUE (identity_id, name)` on
`permissions` plus an `ON CONFLICT (identity_id, name) DO UPDATE` behind a per-identity clear in
`IngestIdentities`. The in-memory inventory path was the remaining half.

**What an operator saw.** `least_privilege` reports "N/M granted permissions unused" and names each
unused grant straight to a human, so a duplicated permission inflated the denominator *and* printed
the recommendation twice. Naming `testdata/agents.json` once, then twice, against the unfixed tree
(@measured `go run ./cmd/idryx detect --load agents:./testdata/agents.json [--load ...]`,
2026-08-06):

```
once   2/3 granted permissions unused, recommend revoking: s3_delete, slack_post
twice  4/6 granted permissions unused, recommend revoking: s3_delete, s3_delete, slack_post, slack_post
```

After the fix the two invocations print the identical line, and the run total is 11 alerts either
way (@measured, same commands, 2026-08-06). Both regression tests were run against the unfixed tree
first and failed on the append itself rather than on a typo (@measured `go test ./internal/graph/
-run 'TestAddIdentityDedupesPermissionsByName|TestAddIdentityMergesPermissionFlags'`, 2026-08-06):

```
store_test.go:299: permissions after re-ingesting the identical inventory 2x =
                   [slack_post s3_read slack_post s3_read], want 2 (deduped by name)
store_test.go:357: permissions = [{Name:AdministratorAccess Admin:false Used:false ARN:}
                   {Name:AdministratorAccess Admin:true Used:true ARN:arn:aws:...}], want exactly 1
```

Fixed by unioning permissions by name in `mergePermissions`. Where two reports of one grant meet,
each field follows the rule its kind already follows one scope up: booleans OR (like `Privileged`
and `Shadow`), a non-empty string wins and an empty one never clears (like `Source` and `Runtime`).
That direction is the safe one for an identity plane. `Admin` and `Used` are positive evidence that
somebody observed something, and a later source reporting neither has usually not contradicted it,
only failed to look; letting it win would turn a used admin grant back into an unused ordinary one
in the operator's report.

**Where the two backends still differ, deliberately named rather than claimed away.** In-memory now
unions across sources; Postgres replaces an identity's whole permission set per `IngestIdentities`
call. Nothing is double-counted on either side, which is what this fix was about, but two sources
each describing part of one identity's grants converge differently. That gap is not reachable from
today's CLI: `idryx load --db` takes exactly one source file per invocation and has no `--load`
list, so cross-source stitching exists only on the in-memory path. It becomes reachable the moment
`load` grows one. @claude, from reading `runLoad` and `IngestIdentities`, not from a run.

**What this did not establish.** No Postgres was involved: `internal/graph/pgstore_integration_test.go`
sits behind the `integration` build tag and needs a live database, so the claim that the Postgres
backend never had this bug is read off the schema and the upsert, not measured against a server. The
in-memory side is measured, both at the unit boundary and through the real CLI. The merge rule is
also pinned only for the fields `model.Permission` has today (`Name`, `Admin`, `Used`, `ARN`); a
field added later gets no rule from these tests and will merge by whatever `mergePermission` says at
that point, which is a line somebody has to remember to write.
=======
## The shared contract was four minor versions stale, and the delta was the integrity check

*The four sections below open with 2026-08-05, the date of the read-only audit that found
them, matching the sections above. Their `@measured` markers carry 2026-08-06, the date the
fixes and their runs actually happened: a measurement is true about its own moment, and dating
one to the day the defect was found would be the first thing to decay.*

2026-08-05, from the same read-only audit. `go.mod` pinned
`github.com/TAIPANBOX/agent-stack-go v0.3.0` while the module was tagged through v0.5.1, and
everything added to its wire packages since v0.3.0 is one file: `event/chain.go`, the SPEC 6.5
`prev_hash` tamper-evidence chain (`Canonicalize`, `ChainHash`, `VerifyChain`, `ChainedWriter`).
So idryx ingested append-only agent-event NDJSON with no integrity check available to it at all,
while AGENTS.md invariant 3 names that module the single pinned source of the wire types. An
identity plane that reads a log somebody else appends to, and cannot say whether the log it read
is the log that was written, is missing the one property the format was given for it.

Fixed by bumping the pin to v0.5.1 and calling `event.VerifyChain` on every agent-event-bus
ingest (`internal/ingest/tokenfuse`), with the verdict carried in the connector's existing
`Report` and printed by `cmd/idryx`'s existing `reportTokenFuse` path. The verification is a
second pass over the same bytes rather than an inline copy of the hashing rule inside `Parse`'s
own loop, on purpose: a second implementation of the wire contract in this repository is exactly
the drift invariant 3 exists to prevent.

**A broken chain is reported, loudly, and is never fatal.** Idryx is a detection tool whose value
is noticing tampering. Refusing to ingest a stream that shows evidence of tampering would hand an
attacker a way to delete every finding in a file by editing one line of it, and the events are
still evidence: the chain says they may not be all of it, or not as written. It also matches the
connector's existing contract (SPEC 6.1/6.7): a content problem is counted and reported, never a
reason to abort the file. What the fix does add is that **an operator can tell "the log was
intact" from "nobody checked"**, which before this was the same silence. Every bus ingest now
prints exactly one of four lines: chain intact (with the counts), chain BROKEN (with each break's
file and physical line number), no `prev_hash` chain present at all, or chain not checked. A
legal restart is not a break, per the spec and `VerifyChain`'s own distinction: it is a second
chain head, and the tests hold that.

Before the fix, none of this compiled, because the pinned module had no chain package at all
(@measured `go test ./internal/ingest/tokenfuse/`, 2026-08-06, against the unfixed tree):

```
# github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse [github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse.test]
internal/ingest/tokenfuse/chain_test.go:19:18: undefined: event.NewChainedWriter
internal/ingest/tokenfuse/chain_test.go:68:10: rep.Chain undefined (type Report has no field or method Chain)
...
FAIL	github.com/TAIPANBOX/idryx/internal/ingest/tokenfuse [build failed]
```

The operator-facing half was driven separately, against the bumped module but the unfixed
reporting path, so a green connector could not stand in for a silent CLI (@measured `go test
./cmd/idryx/ -run Chain`, 2026-08-06):

```
--- FAIL: TestReportTokenFuseChainStatesAreDistinguishable (0.00s)
    main_test.go:835: an intact chain must say so, naming the stream, got ""
    main_test.go:848: a stream with no chain must say so, got ""
    main_test.go:860: a break must be reported with its position, got ""
--- FAIL: TestPopulateVerifiesChainOnIngest (0.00s)
    main_test.go:889: expected the chain break reported with its file and position, got ""
--- FAIL: TestPopulateReportsAnIntactChain (0.00s)
    main_test.go:912: expected an intact-chain statement on stderr, got ""
```

All ten pass after the fix, and the fixtures they verify are written by the shared module's own
`ChainedWriter` rather than by hand, so the bytes under test are the bytes a real bus producer
writes (@measured `go test ./internal/ingest/tokenfuse/ ./cmd/idryx/`, 2026-08-06, both `ok`).

**What this did not establish.** No tampered stream from a real producer: every fixture here is
written and then edited by the test. The break position is the line AFTER the edited one, which
is correct and is what a hash chain can prove (the first link that no longer holds), not a claim
that idryx identifies the edited record itself. Nothing about a chain that was rewritten
end to end: `prev_hash` is tamper-evidence, not tamper-proof, and a rewriter who re-chains the
whole file passes this check by construction. And the chain verdict is not yet a detector
finding: it reaches the operator on stderr and through `tokenfuse.Report`, not as a
`model.Alert` in the graph, so it does not reach a SIEM sink or the dashboard.

## Two detectors could not fire at all when the graph came from Postgres

2026-08-05, from the same read-only audit. `model.Identity.Shadow` (an MCP server observed in use
but absent from the sanctioned registry) and `model.Identity.DeclaredModels` (the Passport's
declared LLM providers, SPEC 4.5) had no columns in `internal/graph/schema.sql`, were never
written by `IngestIdentities`, and were never read by `Snapshot`. So after
`idryx load --db --source mcp ...`, a later `idryx detect --db` ran `shadow_mcp` and
`agent_shadow_tool` over a graph where every Shadow flag was false, and `undeclared_llm` over one
where every agent had zero declared models. All three returned nothing, with no warning, which is
exactly what a clean estate looks like. AGENTS.md states as a design rule that detectors "run
unchanged against the Postgres backend"; for these two fields the backend disagreed with the
in-memory graph and nothing compared them.

Fixed additively, in the `IF NOT EXISTS` style the file already uses: an `identities.shadow`
column, and an ordered `declared_models` join table (`identity_id`, `position`, `provider`,
`model`, `endpoint`) built exactly like the existing `on_behalf_of` chain table, because a
repeated field with meaningful order is the case that table already solves. Shadow upserts as a
sticky OR (`shadow = identities.shadow OR EXCLUDED.shadow`), matching the in-memory
`Store.AddIdentity`, so a later inventory that omits the flag cannot quietly sanction a shadow
server. Declarations are replaced in place on re-ingest, like permissions and the delegation
chain, so a repeated load refreshes rather than duplicates.

**The check that would have caught it needs no database, which is why it now exists.** Two
non-integration tests read the SQL this package issues and the schema it applies
(`internal/graph/columns_test.go`). The first fails when a column is written and never read back,
read and never written, or named in SQL and never declared in `schema.sql`. The second fails when
a field on `model.Identity`, `model.Permission` or `model.DeclaredModel` has no recorded decision
about where the Postgres backend keeps it, so adding a field forces that decision in the same
change rather than leaving it to be discovered by a detector that silently returns nothing.

The second was red against the unfixed tree (@measured `go test ./internal/graph/`, 2026-08-06):

```
--- FAIL: TestModelFieldsAllHaveAPersistenceDecision (0.00s)
    columns_test.go:257: model.Identity.DeclaredModels claims to live in declared_models.identity_id, which schema.sql does not declare
    columns_test.go:260: model.Identity.DeclaredModels claims to live in declared_models.identity_id, which nothing in this package ever writes
    columns_test.go:257: model.Identity.Shadow claims to live in identities.shadow, which schema.sql does not declare
    columns_test.go:260: model.Identity.Shadow claims to live in identities.shadow, which nothing in this package ever writes
    columns_test.go:263: model.Identity.Shadow claims to live in identities.shadow, which nothing in this package ever reads back
    ...
FAIL	github.com/TAIPANBOX/idryx/internal/graph
```

The first passed against the unfixed tree, because a column that exists nowhere is in neither
list, so it was verified by breaking instead, three ways, each of which fails it for its own
reason (@measured `go test ./internal/graph/ -run TestPgStoreWritesAndReadsTheSameColumns`,
2026-08-06, each mutation applied and reverted in turn):

```
identities.shadow is written and never read back: the value reaches Postgres and no Snapshot ever returns it, so no detector can see it
identities.shadow is read and never written: every row comes back as the schema default, which is indistinguishable from real data
identities.shadow appears in SQL but schema.sql declares no such column, so migrate() leaves it missing
```

**What this did not establish.** The two live-Postgres tests
(`TestPgShadowAndDeclaredModelsRoundTrip`, `TestPgShadowFlagIsStickyLikePrivileged`) were written
and compile under the `integration` tag (@measured `go vet -tags integration ./internal/graph/`,
2026-08-06, clean), and they were NOT run here: this machine has no Postgres and no running
container runtime, so CI's `integration` job is the first place they execute. The
database-free checks above are what actually ran. Nothing here says anything about an existing
production database's migration behaviour beyond the additive `IF NOT EXISTS` shape the rest of
the file already relies on, and no detector was driven end to end over `--db` in this session:
the round trip is asserted at the store boundary (`IngestIdentities` then `Snapshot`), not
through `idryx detect --db`.

## The privilege_escalation detector could not fire from any shipped connector

2026-08-05, from the same read-only audit. `internal/detect/detectors/privilege_escalation.go`
keys its `dangerousPermissions` map on cloud ACTION strings (`iam:passrole`,
`iam.serviceaccounts.actas`, `microsoft.authorization/roleassignments/write`). No connector
produced a name of that shape. `aws_iam` emitted IAM POLICY NAMES from `AttachedManagedPolicies`
and the inline policy lists, and never read `PolicyDocument` at all. `gcp_iam` emitted ROLE names
(`roles/storage.admin`). `azure` emitted `roleDefinitionName` ("Owner", "Contributor"). All three
bundled fixtures confirmed it. The detector's own test built identities by hand with action
strings no connector emits, so it passed while the feature was unreachable from every input idryx
can be given.

Same root, wider blast radius: admin equivalence was decided purely by string-matching names
(`isAdminPolicy`: "administratoraccess" or "admin"), so a customer-managed or inline policy
granting `"Action": "*"` on `"Resource": "*"` under any ordinary name was invisible to
`Identity.HasAdmin()`, and therefore to `excessive_agency`, `over_privileged_nhi`,
`runaway_agent`, `attestation_missing` and `shadow_mcp`.

**How far the parsing goes, and what it deliberately is not.** The aws_iam connector now reads
policy documents: inline documents in both encodings a real export carries (URL-encoded JSON in a
string from the API, a decoded object from the AWS CLI), and the DEFAULT version of each
customer-managed policy from the same call's `Policies` section. From a document it derives the
allowed action strings and whether the grant is administrator-equivalent. Deny statements grant
nothing and are skipped; a `NotAction` list is never read as the actions allowed, which is the
one way a naive reading inverts a statement's meaning. Conditions are not evaluated, so a
conditioned Allow reads as an Allow, which over-reports rather than under-reports. GCP and Azure
have no document to read, so each got a hand-maintained table of what their named roles contain:
the escalation permissions inside the GCP predefined roles that carry one (owner, editor, the
`iam.serviceAccount*` family), and the escalation actions inside the Azure built-in roles.
Contributor is the one worth reading twice: it grants everything EXCEPT authorization writes, so
it does not get `roleAssignments/write`, and a test fails if it ever does, because that would be
a false accusation on one of the most widely assigned roles in Azure.

**What remains, precisely.** A full IAM policy-language evaluator is out of scope and is not
here: no condition evaluation, no `NotResource`, no resource-path matching (an action allowed
only on one bucket ARN reads the same as one allowed on `*`, except for the admin verdict, which
does require `Resource: "*"`), no permission boundaries, no SCPs, no session policies, and no
trust-policy analysis (`sts:AssumeRole` reachability between roles, which is its own graph
problem). AWS-managed policies are still judged by name and ARN, because their documents are not
in this export at all. On GCP, a CUSTOM role's contents are not in a project IAM policy, so a
custom role granting `iam.serviceAccounts.actAs` is still invisible; the same holds for a custom
Azure role definition, since `az role assignment list` reports only the role's name. Both tables
are hand-maintained (`@claude`, 2026-08-06) from documented role contents, not fetched live, so a
provider changing a predefined role's contents is a change nothing here would notice. Closing the
custom-role half means taking a second input (`gcloud iam roles describe`,
`az role definition list`), which is a connector-shaped change, not a detector one.

**The tests are driven from the bundled fixtures, not from hand-built identities**, so what they
prove is the path from connector to detector rather than the detector in isolation, which is the
exact gap that let this ship. Red against the unfixed tree (@measured `go test ./internal/detect/
./internal/graph/`, 2026-08-06):

```
--- FAIL: TestPrivilegeEscalationReachableFromBundledConnectors/aws_iam (0.00s)
        connector_reach_test.go:99: privilege_escalation did not fire for arn:aws:iam::123456789012:role/ci-deployer (an inline policy document allowing iam:PassRole; the connector never read PolicyDocument at all)
    --- FAIL: TestPrivilegeEscalationReachableFromBundledConnectors/gcp_iam (0.00s)
        connector_reach_test.go:99: privilege_escalation did not fire for gcp:ci-deployer@my-proj.iam.gserviceaccount.com (roles/owner contains iam.serviceAccounts.actAs; the connector emitted the role name and nothing knew what is inside it)
    --- FAIL: TestPrivilegeEscalationReachableFromBundledConnectors/azure (0.00s)
        connector_reach_test.go:99: privilege_escalation did not fire for azure:11111111-1111-1111-1111-111111111111 (the Owner built-in role contains Microsoft.Authorization/roleAssignments/write; the connector emitted "Owner")
--- FAIL: TestAdminEquivalenceFromAPolicyDocumentNotAName (0.00s)
    connector_reach_test.go:132: arn:aws:iam::123456789012:role/app-config holds a customer-managed policy allowing * on *, and HasAdmin() is false: every admin-based detector is blind to it
    connector_reach_test.go:139: over_privileged_nhi did not fire for arn:aws:iam::123456789012:role/app-config, whose policy document grants everything on everything
```

**What was added to the fixtures**, since a test that invents its own input proves less than one
that reads what ships. `testdata/aws_iam.json` gained: a `PolicyDocument` on the existing
`inline-s3-read` inline policy (`s3:GetObject`, `s3:ListBucket` on one bucket, the benign case
that must NOT fire); a `ci-deployer` role whose inline policy is URL-encoded exactly as the API
returns it and allows `iam:PassRole`; an `app-config` role attached to a customer-managed policy
under the ordinary name `AppConfigAccess`; and a top-level `Policies` section for that policy
with two versions, where the non-default v1 allows one appconfig read and the DEFAULT v3 allows
`*` on `*`. That last shape is doing two jobs: it is the admin-equivalence case, and it is the
regression test for reading the wrong version, since a connector that took v1 would report a
narrow policy that was widened. The GCP and Azure fixtures needed nothing added: `roles/owner`
and `Owner` were already there and were already unreachable.

The fix is visible in the shipped demo, not only in tests (@measured
`./bin/idryx detect --source aws_iam ./testdata/aws_iam.json`, 2026-08-06):

```
high  over_privileged_nhi   arn:aws:iam::123456789012:role/app-config   NHI holds admin-equivalent permissions
high  privilege_escalation  arn:aws:iam::123456789012:role/ci-deployer  NHI holds dangerous escalation permission "iam:passrole" via grant "deploy-service-roles" (AWS: Allow passing roles to AWS services)
```

**Folded in, on inspection.** The derived actions had to reach Postgres too, or this fix would
have reintroduced the defect above one level down: the detector would fire from a file and stay
silent over `--db`. They persist in an ordered `permission_actions` child table, and the
persistence ratchet added earlier is what caught it, immediately and by name
(`model.Permission.Actions has no persistence decision`). Separately, `matchDangerous`'s fallback
scan iterated a Go map, so a permission string containing two escalation names reported whichever
one map iteration reached first: a summary that could differ between runs on identical input,
against invariant 1. It now iterates a sorted key list.

**What this did not establish.** No real cloud export from a real account: every fixture here is
hand-written to the documented shape of `aws iam get-account-authorization-details`,
`gcloud projects get-iam-policy` and `az role assignment list`. Nothing was run against AWS, GCP
or Azure. The GCP and Azure role tables are assertions about what those providers' roles contain,
taken from documentation rather than measured against a live IAM API, and they are the part of
this change most likely to age. And `permission_actions` was exercised through the
`integration`-tagged round-trip test, which needs a Postgres this machine does not have, so CI is
the first place it runs.

## Two flags were accepted, documented, and silently ignored

2026-08-05, from the same read-only audit. Both are applied now rather than refused, with one
narrow exception stated below.

**`--privileged` did nothing whenever `--db` was used.** `buildGraph`'s Postgres branch returned
the snapshot without ever referencing its `privileged` parameter; the set was applied only at
`idryx load` time. Ten detectors raise severity for a privileged identity, so
`idryx detect --db --privileged alice@x.com` ranked alice exactly as if she had not been named,
and the output carried nothing to say so. An operator who learns after loading that an identity
matters had no way to tell idryx. Fixed with `graph.Store.MarkPrivileged`, which folds the set
into a graph that already exists: it marks the identities present and remembers the set for any
created later, matching what `New(privileged)` has always done. An identity named in the set but
absent from the graph is not invented, because `--privileged` says which identities matter more,
not which exist.

**`--cloudtrail` and `--gcp-audit` did nothing in `--load` mode.** `loadList.Set` populated only
`Source` and `Path`, so the `CTPath`/`AuditPath` of every spec built from `--load` stayed empty,
the usage-enrichment paths in `populate` were unreachable, and `least_privilege` (which stays
silent without usage data, by design) said nothing. Passing the flag and omitting it produced
identical output. Fixed by attaching the run's usage paths to each `--load` spec whose source can
use them, which is the same thing the single-`--source` path already did.

**Where a flag cannot apply at all, it is now an error naming the combination**, which is the
"or refuse" half: `--cloudtrail` with no `aws_iam` source anywhere in the run, `--gcp-audit` with
no `gcp_iam`, and either with `--db`, where the graph comes from the database and enrichment
happened (or did not) at `idryx load` time. The check runs before the database is opened, so the
operator gets the flag error rather than a connection error. This also closes the same silent
ignore on the single-`--source` path, which had it too (`--source okta --cloudtrail ct.json` was
accepted and dropped).

Red against the unfixed tree, at both levels (@measured `go test ./internal/graph/` and
`go test ./cmd/idryx/ -run 'LoadMode|UsageFlag'`, 2026-08-06):

```
internal/graph/store_test.go:274:4: s.MarkPrivileged undefined (type *Store has no field or method MarkPrivileged)
FAIL	github.com/TAIPANBOX/idryx/internal/graph [build failed]
```

```
--- FAIL: TestLoadModeAppliesCloudTrailEnrichment (0.00s)
    main_test.go:941: no permission was marked used, so --cloudtrail did nothing in --load mode
--- FAIL: TestLoadModeAppliesGCPAuditEnrichment (0.00s)
    main_test.go:966: no role was marked used, so --gcp-audit did nothing in --load mode
--- FAIL: TestUsageFlagWithNoMatchingSourceIsAnError/cloudtrail_with_an_okta_load (0.00s)
        main_test.go:1019: expected an error naming --cloudtrail, got none: the flag was accepted and ignored
--- FAIL: TestUsageFlagWithNoMatchingSourceIsAnError/cloudtrail_with_--db (0.61s)
        main_test.go:1022: error = "ping postgres: failed to connect to `user=factory database=`: ... lookup unused: no such host", want it to name --cloudtrail so the operator knows which flag did nothing
```

That last line is worth keeping: the `--db` case failed by trying to CONNECT first, which is why
the check now runs ahead of `graph.OpenPg` rather than inside the branch.

**What this did not establish.** The `--privileged` fix is proven at the store boundary by a test
that needs no database (`TestMarkPrivilegedAppliesToAnAlreadyBuiltGraph`), and end to end by
`TestDetectDBAppliesPrivilegedFlag`, which is `integration`-tagged, needs a real Postgres, and
did NOT run here: this machine has no Postgres and no running container runtime. CI's
`integration` job now covers `./cmd/idryx/` as well as `./internal/graph/`, so that is where it
first executes. Nothing here changes what `idryx load --db --privileged` does; it already applied
the set, and it still does.
>>>>>>> origin/main
