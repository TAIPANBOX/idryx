# Compatibility

`TAIPANBOX/idryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: proposed: this repository is at 0.x, and the surface named here is what its 1.0 will freeze; the gate holds it from today so that 1.0 is a tag and not a rewrite

## Frozen

### cli.exit_codes (1)

- `exitSinkDelivery=3`
- held in: `cmd/idryx/main.go`

### cli.subcommands (8)

- `detect`
- `bom`
- `ai-inventory`
- `serve`
- `load`
- `remediate`
- `ebpf-capture`
- `version`
- held in: `cmd/idryx/main.go`

### env (3)

- `IDRYX_OTLP_ENDPOINT`
- `IDRYX_EVENTS`
- `IDRYX_TRUST_DOMAIN`
- held in: `cmd/idryx/main.go`

### events.consumed (10)

- `budget_exhausted`
- `sustained_loop`
- `spend_spike`
- `fanout_explosion`
- `breaker_tripped`
- `dlp_block`
- `taint_block`
- `mcp_drift`
- `web_fetch`
- `web_blocked`
- held in: `internal/ingest/tokenfuse/tokenfuse.go`

### events.emitted (1)

- `identity_finding`
- held in: `internal/events/events.go`

### formats (2)

- `CycloneDX`
- `1.6`
- held in: `internal/bom/cyclonedx.go`

### http.routes (4)

- `/api/alerts`
- `/api/identities`
- `/api/remediations`
- `/healthz`
- held in: `internal/server/server.go`

## Additive within a major

- a detector: a new one is a new finding, never a removed one
- a CLI flag on an existing subcommand
- a connector source
- an event type in events.consumed
- the agent-event schema version this repository emits, which moves in its own release (agent-passport SPEC 6.4.1)

## Experimental

- the egress log JSON that ebpf-capture writes
- the dashboard HTML

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
