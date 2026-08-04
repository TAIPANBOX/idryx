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
