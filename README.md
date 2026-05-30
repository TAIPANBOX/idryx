# idryx — Identity Security Graph

A security layer on top of your existing IdPs, clouds, and gateways. idryx reads
the data Okta/Entra/AWS/GCP/Azure/Keycloak already generate, stitches every
identity type — humans, service accounts, keys, and AI agents — into a single
graph, and surfaces excessive privilege and anomalous behavior. Open-core,
dev-first, built for mid-market.

## Why
The identity market is fragmented: ITDR sees logins, NHI tools see keys, IAM tools
see permissions. Attacks travel through the seams between them. idryx sees all
dimensions at once and answers the question nobody answers today:

> "This identity (human/service/agent) has too much privilege, hasn't been touched
> in a long time, and just behaved abnormally — here is the owner and what is at
> risk."

By 2026, non-human identities and AI agents outnumber humans roughly 100:1, yet
68% of companies don't monitor them; 47% of NHIs haven't changed in over a year.

## What it does
1. **Ingest** — read-only connectors to IdPs, clouds, secrets stores, GitHub,
   Kubernetes, and agent runtimes, normalized into one model.
2. **Graph** — every identity type and its permissions, events, owners, and
   delegation chains in a single Identity Graph.
3. **Baseline + detection** — per-identity normal behavior; deterministic
   detection of anomalies and excessive privilege (ITDR, NHI, least-privilege).
4. **Remediation** — least-privilege recommendations and rotation, delivered as
   PRs and alerts (SIEM/Slack/OTLP).

See [`idryx-plan.md`](./idryx-plan.md) for the full design and roadmap.

## Architecture
One core (graph + baseline + detection), many connectors on the input. Each
direction — ITDR, NHI, least-privilege, eBPF, agents — is a new connector of the
same core, not a separate product. The LLM is used only as an interface (NL
queries, explanations), never in the detection path, which stays deterministic and
auditable.

## Stack
- Core/ingest: Go (Rust for hot paths)
- Graph: Postgres (with recursive CTEs) → graph DB if needed
- Analytics/baseline/detection: Python
- API: Go (gRPC/REST)
- UI: TypeScript (React)
- License: open-core (Apache-2.0 core + paid connectors/enforcement/SaaS)

## Quick start
```bash
make build
./bin/idryx detect <log.json>                       # human-readable report
./bin/idryx detect --format json <log.json>         # JSON alerts
./bin/idryx detect --source entra <log.json>        # okta | entra | cloudtrail
./bin/idryx detect --privileged alice@x.com ...     # mark privileged accounts
```

Run against the bundled fixtures:
```bash
make detect
```

## What works today
A CLI that ingests an identity log, normalizes it into an in-memory identity
graph, builds per-identity behavioral baselines, and runs deterministic
detectors.

**Source connectors** (normalize into one shared event model):
- `okta` — Okta System Log
- `entra` — Microsoft Entra ID sign-in log (Graph API)
- `cloudtrail` — AWS CloudTrail (ConsoleLogin + API activity for NHIs/roles)

**Detectors:**
- `impossible_travel` — two successful logins too far apart to be feasible
- `mfa_fatigue` — a burst of MFA challenges in a short window (push-bombing)
- `new_device` — a privileged identity logging in from an unseen device
- `behavior_anomaly` — login deviating from the identity's learned baseline
  (new country/device/active-hour), scored 0–1

The **baseline engine** (`internal/baseline`) learns what is normal per identity
and suppresses scoring during a learning period to avoid false positives — the
same engine that will later extend to service accounts and AI agents. Detection
is deterministic (statistics + rules over the graph); LLMs are never in the
detection path. `--privileged` raises severity for sensitive accounts.

## Status
Phase 1 in progress: baseline engine and Entra + CloudTrail connectors landed on
top of the Phase 0 ITDR core. Next, per [`idryx-plan.md`](./idryx-plan.md):
Postgres-backed graph, web UI, and SIEM/Slack alerting.

## License
Apache-2.0.
