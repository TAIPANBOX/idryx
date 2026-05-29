# idryx — Identity Security Graph

## Essence
A security layer on top of other vendors' IdPs / clouds / gateways. Not your own
Okta, not your own gateway. idryx reads the data Okta/Entra/AWS/Keycloak already
generate, stitches every identity type (humans + service accounts + keys + AI
agents) into one graph, and finds excessive privilege and anomalous behavior.

**The edge competitors don't have:** every identity type in one graph. The market
is fragmented — ITDR sees logins, NHI tools see keys, IAM tools see permissions.
Attacks travel through the seams. idryx sees all dimensions at once.

The answer nobody gives today:
> "This identity (human/service/agent) has too much privilege, hasn't been touched
> in a long time, and just behaved abnormally — here is the owner and what is at
> risk."

## Problem (with numbers)
1. Blindness: NHIs/agents outnumber humans ~100:1 (2026). 68% of companies don't
   monitor them.
2. Privilege accumulation: 47% of NHIs haven't changed in over a year.
3. Late detection: stolen credentials = 38% of breaches, discovered weeks later.
4. Agent explosion: Gartner — 40% of enterprise apps will include agents by the
   end of 2026 (from <5%); governance lags production 8:1. agentic spend
   $201.9B/2026.

## Target buyer
SecOps / IAM teams at mid-to-large companies that already run Okta/Entra/AWS and
have chaos with non-human identities. They don't replace the IdP — they pay extra
for visibility and security on top of it.

---

## Architecture

```
Sources (read-only connectors):
  Okta / Entra / Keycloak  ─┐
  AWS CloudTrail / IAM      ─┤
  GCP Audit Logs / IAM      ─┤
  Azure Activity / RBAC     ─┤──► Ingest/normalize ──► Identity Graph
  Secrets (Vault/SM)        ─┤                            │
  GitHub / CI-CD            ─┤                            ▼
  Kubernetes                ─┤        Baseline engine (what is normal per identity)
  MCP / agent runtimes      ─┘                            │
                                                          ▼
                                       Detection engine (anomalies + excess privilege)
                                                          │
                              ┌────────────────────────────┤
                              ▼                             ▼
                        Alerts / ITDR              Right-sizing recommendations
                        (SIEM, Slack, OTLP)        (least-privilege, rotation)
```

Key: **one core (graph + baseline + detection), many connectors on the input.**
Each direction (ITDR, NHI, least-privilege, eBPF, agents) = a new connector of the
same core, not a separate product.

## Graph data model (sketch)
- **Identity** {type: human|service_account|key|token|agent, owner, source, created, last_used}
- **Permission** {action, resource, condition, granted_by}
- **Event** {identity, action, resource, time, src_ip, device, geo}
- **Relationship** edges: identity→permission, identity→event, identity→owner,
  permission→escalation_path, agent→on_behalf_of
- Queries: "escalation paths to admin", "orphaned identities", "over-privileged vs
  used", "anomalous event + permission context".

## Multi-cloud: source-service mapping
The graph normalizes three clouds into one model. Connectors pull equivalent
signals:

| Signal | AWS | GCP | Azure |
|---|---|---|---|
| Events (audit) | CloudTrail | Cloud Audit Logs (Admin Activity + Data Access) | Azure Activity Log + Entra sign-in/audit |
| Identities | IAM users/roles, STS | Service accounts, IAM members | Entra service principals, Managed Identities |
| Permissions | IAM policies | IAM role bindings | Azure RBAC role assignments |
| Keys/secrets | Access keys, Secrets Manager | SA keys, Secret Manager | Entra app secrets/certs, Key Vault |
| Least-privilege | Access Analyzer (with CloudTrail) | IAM Recommender / Policy Analyzer | Entra Permissions Management (CloudKnox) / PIM |

Normalizing to a shared model (Identity/Permission/Event) is what enables
cross-cloud correlation: one over-privileged identity, seen identically across all
three. That is the difference from single-cloud tools.

Note: Entra ID appears twice — as an IdP connector (human logins) and as a source
of Azure identities (service principals / managed identities). One connector, two
signal types.

---

## AI-identity: agents as first-class identities

A separate section because this is the hottest vector (agentic spend
$201.9B/2026; OWASP ranks Prompt Injection and Excessive Agency among top critical
threats; EU AI Act — the August 2, 2026 deadline is in force, Art. 49 public AI
registration).

**Competitive reality (as of 2026) — no illusions.** The graph is no longer
unique: Permiso (Universal Identity Graph, cross-cloud ISPM+ITDR), Wiz (Security
Graph, attack paths), CrowdStrike (cross-domain correlation, Leader GigaOm ITDR
2026), BeyondTrust (CIEM+ITDR+PAM, "industry-first agent governance"). The
inventory game is taken by Astrix (acquired by Cisco, ~$300M), Token, Oasis ($120M
Series B). IdPs are embedding agent-identity already: Okta for AI Agents (GA
2026-04-30), Entra Agent ID, Google Vertex Agent Identity.

**Where the gap for idryx remains (narrow, but real):**
1. **Open-core** against everyone — competitors are closed/enterprise-priced; OSS
   delivers adoption, self-hosting for regulated environments, dev trust.
2. **Mid-market / dev-first** — the big players target Fortune 1000; underneath
   them it's empty.
3. **Detecting agent compromise by behavior in the graph** — everyone does
   inventory/governance, agent behavioral-compromise is still early.
Inventory as the main product is a losing game. The angle = detection +
enforcement + open-core, not visibility.

### What we add to the graph model
- `Identity.type` gains the value `agent`; fields `runtime` (where it executes) and
  `delegation_depth`.
- A multi-level `on_behalf_of` edge: `agent → sub-agent → service account →
  human owner`. Gives transitive computation of effective permissions at the end of
  the chain.
- An `agent → tool/scope` edge (MCP tools, API scopes).

### Four features (in descending value and implementation readiness)

**1. Agent compromise as a behavioral anomaly (Phase 2-4, existing engine).**
The same baseline engine that catches impossible travel for humans catches intent
drift for an agent: baseline "reads Jira" → suddenly `send_email` to an external
domain or reading a secret. This detects the consequences of prompt-injection /
tool-poisoning / memory-poisoning **without inspecting the prompt**, by the
identity's actions (OWASP LLM01; "Agent Goal Hijack" in OWASP Agentic Top 10
2026). Validated as a working approach (ARMO intent-drift, AgentArmor) and by real
2026 incidents (Moltbook — 506 prompt injections; OpenAI plugin supply-chain — 47
enterprises, 6 months unnoticed; Vercel pivot via Context.ai). Our differentiator
from ARMO/Operant: they are runtime/eBPF-only; we correlate the network signal
(Phase 4) WITH the identity and its permissions in the graph.

**2. Blast radius / delegation graph (Phase 2-3).**
"Excessive Agency" (OWASP LLM06) becomes measurable: an agent's blast radius
through the delegation chain down to cloud permissions. The graph uniquely shows
the transitive path; single-tool competitors would have to rewrite. Directly
reinforces the moat thesis.

**3. Shadow AI / AI-BOM (Phase 2, easy win).**
Which key talks to `api.openai.com`/`api.anthropic.com`, which service leaks data
into an LLM, who spun up an unsanctioned agent. Visible from existing sources
(CloudTrail egress, secrets usage, GitHub connector). Compliance driver: EU AI Act
Art. 6 — "the obligation to know", fines up to €15M / 3% of turnover, deadline
August 2026. Same buyer, new sales angle.

**4. MCP as an attack surface (Phase 3-5).**
MCP servers are a new perimeter (spec: OAuth 2.1 + PKCE, RFC 8707; OWASP MCP Top
10: Shadow MCP Servers, tool poisoning — rug pulls / schema poisoning / tool
shadowing; real CVEs e.g. CVE-2025-6514). A connector to the MCP registry +
shadow-MCP discovery + least-privilege on the `agent↔tool` relationship. Fits the
existing "granted vs used" logic.

### LLM inside the product — the boundary
We use LLMs **only as an interface, not in the detection path:**
- Yes: Graph-RAG / NL queries to the graph, explaining alerts and least-privilege
  diffs in natural language, a triage copilot for SecOps.
- No: an LLM in the detection decision itself. Detection is deterministic
  (statistics/rules/graph), explainable and auditable. Otherwise hallucinations
  kill SecOps trust — and trust in the core is the product.

### Standards — watch, don't build the foundation on them
AIMS (IETF draft-klrc-aiagent-auth, Mar 2026), WIMSE (draft-02 for agents),
SPIFFE+OAuth, RFC 8693 token exchange, ID-JAG, NIST NCCoE + AI Agent Standards
Initiative (Feb 2026) — all still drafts, but already with vendor implementations
(Okta for AI Agents GA 2026-04-30, Entra Agent ID). idryx reads them as sources
and normalizes, rather than implementing any one as the foundation. Okta/Entra
embedding agent-identity is simultaneously a threat (basic visibility becomes free)
and proof of the need for a cross-vendor correlation layer on top of them.

## Stack
- Core/ingest: **Go** (event streaming, connectors) or Rust for hot paths.
- Graph: Postgres first (with recursive CTEs) → graph DB if needed.
- Analytics/baseline/detection: **Python** (statistics, anomalies).
- API: Go (gRPC/REST).
- UI: **TypeScript** (React).
- Export: OTLP / Prometheus / SIEM connectors.
- License: open-core (OSS core + paid connectors/enforcement/SaaS).

---

## Roadmap (phases)

### Phase 0 — ITDR prototype (2-3 weeks)
- Connector to Okta (System Log API) → event normalization.
- Minimal graph in Postgres (identities + events).
- 3 detections: impossible travel, MFA fatigue, new device for a privileged
  account.
- CLI alert output.
- **Go/no-go:** can we see a real threat on someone else's tenant within an hour.

### Phase 1 — ITDR MVP (1-1.5 months)
- Connectors: Okta + Entra + CloudTrail.
- Baseline engine (per-identity normal behavior).
- Detection set (impossible travel, token reuse, privilege escalation, anomalous
  time/geo).
- Web UI: identity list, graph, alert feed.
- Alert integrations: Slack + SIEM (OTLP/syslog).
- **Demo scenario:** connected Okta → within an hour showed suspicious logins.

### Phase 2 — NHI module (incl. agents), multi-cloud (1.5 months)
- Connectors: AWS IAM, GCP IAM (service accounts), Azure (service principals +
  managed identities), Vault/Secret Manager/Key Vault, GitHub.
- Inventory of non-human identities from all three clouds in one graph.
- **Agent = an NHI subtype:** inventory of agents and delegation chains in the same
  graph.
- **Shadow AI / AI-BOM:** detecting unsanctioned LLM/agent integrations via
  egress + secrets usage + GitHub (EU AI Act compliance angle).
- Detection: orphaned, stale (>N days), over-privileged — identical across clouds.
- Owner-mapping + rotation/revocation recommendations.
- Start with AWS (Phase 2a), then GCP+Azure as separate connectors (2b) on the same
  engine.

### Phase 3 — Least-privilege (#1), multi-cloud (1.5 months)
- Granted vs actually used (action-level) per cloud:
  - AWS: CloudTrail → policy, working around Access Analyzer limits (own pipeline).
  - GCP: Audit Logs + IAM Recommender → minimal role bindings.
  - Azure: Activity Log + Permissions Management/PIM → minimal RBAC assignments.
- Generate a diff + an explanation for each action, a shared recommendation format.
- PRs to Terraform (supports all three) as the single application channel.
- **Least-privilege for agents:** the same "granted vs used" analysis on the
  `agent↔MCP-tool/scope` relationship; trimming excessive agency (OWASP LLM06).

### Phase 4 — Behavioral network layer (#4) (1.5 months)
- eBPF sensor (aya, Rust): flow, timing, TLS ClientHello.
- Beaconing detection (periodogram/autocorrelation), JA3/JA4, DNS tunneling.
- Correlating the network signal with the identity in the graph.

### Phase 5 — Agent enforcement / MCP authz (when standards mature)
Agent visibility and detection moved to Phases 2-4 (agent = an NHI subtype). What
remains here is only enforcement, which depends on immature standards:
- A connector to agentgateway / MCP (we do NOT build a gateway — we integrate).
- Authz policies agent→tools/scopes in blocking mode (not just recommendations).
- JIT access and auto-revocation for agents.
- Audit of "who did what on whose behalf" (prepared by the Phase 2 delegation
  graph).

---

## Strategy
- **Architecture as a platform** (connectors/baseline/detection — separate layers).
- **Sell narrow** (ITDR first), expand via connectors.
- Profit in different directions arrives SEQUENTIALLY, once the core has paid off on
  the first.

## Monetization (open-core)
OSS core (trust, adoption) → paid: additional connectors, enforcement
(auto-rotation, JIT access, blocking), SaaS hosting, compliance reports. The check
grows with the number of identities and depth (detection → enforcement →
governance).

## Moat
- Accumulated baselines (the longer it runs, the more accurate the detection, the
  harder to leave).
- Open-core community + connectors: faster adoption and self-hosting where closed
  enterprise tools (Permiso/Wiz) aren't allowed.
- Cross-type correlation — still valid against NHI-only tools (Astrix/Token),
  weaker against Permiso/CrowdStrike; do not rely on it alone.
- Behavioral detection of agent compromise — still early for everyone; a window of
  leadership.

## Risks
- Acquisition by giants (Okta/CrowdStrike/MS buying up ITDR/NHI) — simultaneously
  an exit scenario.
- The graph is no longer unique (Permiso/Wiz/CrowdStrike/BeyondTrust have
  cross-domain graphs) → differentiate via open-core + mid-market + agent
  behavioral-detection, not via the mere fact of a graph.
- Consolidation has begun (Cisco↔Astrix ~$300M, Oasis $120M B) — a narrow window;
  also an exit scenario via acquisition.
- IdPs will embed basic visibility (Okta for AI Agents GA 2026-04, Entra Agent ID)
  for free → focus on enforcement + cross-vendor correlation, not inventory.
- Agent standards (AIMS/WIMSE/SPIFFE) are still drafts and competing → agents a
  module, not the foundation.
- LLM hallucinations will undermine trust → keep the LLM out of the detection path
  (interface only).
- OSS adoption ≠ revenue → build monetization in from day one.
- CloudTrail without data events → risk of cutting needed permissions (warn,
  expand incrementally).

## Next steps
1. Stand up the idryx repository (idryx.io is free; .com is taken — fine for a tech
   product).
2. Phase 0: Okta connector + minimal graph + 3 ITDR detections.
3. Find 1-2 pilot tenants to validate the demo scenario.
