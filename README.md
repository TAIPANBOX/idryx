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
./bin/idryx detect <okta-system-log.json>                 # human-readable report
./bin/idryx detect --format json <okta-system-log.json>   # JSON alerts
./bin/idryx detect --privileged alice@x.com,bob@x.com ... # mark privileged accounts
```

Run against the bundled fixture:
```bash
make detect
```

## What works today (Phase 0)
A CLI that ingests an Okta System Log export, normalizes it into an in-memory
identity graph, and runs 3 ITDR detectors:
- `impossible_travel` — two successful logins too far apart to be feasible
- `mfa_fatigue` — a burst of MFA challenges in a short window (push-bombing)
- `new_device` — a privileged identity logging in from an unseen device

Detection is deterministic (statistics + rules over the graph), and the
`--privileged` set raises severity for sensitive accounts. The Okta connector
(`internal/ingest`) normalizes source logs into a shared event model, so adding
Entra/CloudTrail later is a new connector, not a new engine.

## Status
Phase 0 (MVP CLI detector) — working. Next, per [`idryx-plan.md`](./idryx-plan.md):
Postgres-backed graph, a baseline engine, Entra + CloudTrail connectors, web UI,
and SIEM/Slack alerting.

## License
Apache-2.0.
