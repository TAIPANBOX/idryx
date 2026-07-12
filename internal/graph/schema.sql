CREATE TABLE IF NOT EXISTS identities (
    id           TEXT PRIMARY KEY,
    privileged   BOOLEAN NOT NULL DEFAULT FALSE,
    type         TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    owner        TEXT NOT NULL DEFAULT '',
    created      TIMESTAMPTZ,
    last_used    TIMESTAMPTZ,
    runtime      TEXT NOT NULL DEFAULT '',
    parent       TEXT NOT NULL DEFAULT '',
    attestation  TEXT NOT NULL DEFAULT ''
);

-- Ensure existing database instances are migrated if they only have the Phase 0/1 columns.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS created TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_used TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS runtime TEXT NOT NULL DEFAULT '';

-- Passport-file ingestion (agent-passport SPEC §4.2/§4.3): the agent's
-- static provisioning parent and its attestation posture. Both are
-- capture-only metadata from a Passport document, distinct from the dynamic
-- on_behalf_of chain below (§5).
ALTER TABLE identities ADD COLUMN IF NOT EXISTS parent TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS attestation TEXT NOT NULL DEFAULT '';

-- Phase 5.1: OnBehalfOf became a full delegation chain (agent-passport SPEC §5:
-- ordered root-first, last = immediate principal) instead of one hop, so the
-- single self-referencing on_behalf_of column is replaced by an ordered join
-- table. Principals are opaque strings (agent://, user://, or legacy plain
-- IDs) that may not (yet) have their own identities row, so this table
-- intentionally has no FK on principal — only on the owning identity.
CREATE TABLE IF NOT EXISTS on_behalf_of (
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    position    INT  NOT NULL,
    principal   TEXT NOT NULL,
    PRIMARY KEY (identity_id, position)
);

-- Backfill: a legacy single-hop on_behalf_of value is exactly a chain of
-- length one, i.e. position 0. Guarded on the old column still existing so
-- re-running this script is a no-op (matching the additive IF NOT EXISTS
-- style used above), and ON CONFLICT DO NOTHING so a partially-migrated
-- database is never overwritten. Only after the backfill is the old column
-- dropped — the migration never discards data.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'identities'
          AND column_name = 'on_behalf_of'
    ) THEN
        INSERT INTO on_behalf_of (identity_id, position, principal)
        SELECT id, 0, on_behalf_of FROM identities
        WHERE on_behalf_of IS NOT NULL AND on_behalf_of <> ''
        ON CONFLICT (identity_id, position) DO NOTHING;
    END IF;
END $$;

ALTER TABLE identities DROP COLUMN IF EXISTS on_behalf_of;

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    type        TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    city        TEXT NOT NULL DEFAULT '',
    country     TEXT NOT NULL DEFAULT '',
    lat         DOUBLE PRECISION NOT NULL DEFAULT 0,
    lon         DOUBLE PRECISION NOT NULL DEFAULT 0,
    device      TEXT NOT NULL DEFAULT '',
    resource    TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT ''
);

-- Ensure existing event tables have the resource column for shadow_ai
ALTER TABLE events ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

-- Producer-assigned event severity (agent-passport SPEC §6.1), used by the
-- tokenfuse source; empty for sources without the concept.
ALTER TABLE events ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS events_identity_ts ON events (identity_id, ts);

-- Re-running `idryx load --source okta okta.json` twice (or naming the same
-- file in --load more than once) re-parses and re-inserts every event.
-- Without a natural-key constraint, Ingest's plain INSERT doubled every
-- event, inflating threshold detectors like mfa_fatigue (3 genuine
-- challenges became 6 and crossed the fire threshold). Remove any
-- duplicates a prior double-ingest left behind, keeping the lowest
-- surrogate id, so this migration is safe to apply to an already-affected
-- database before the unique index is created below.
DELETE FROM events a USING events b
WHERE a.id > b.id
  AND a.identity_id = b.identity_id
  AND a.ts = b.ts
  AND a.type = b.type
  AND a.outcome = b.outcome
  AND a.ip = b.ip
  AND a.city = b.city
  AND a.country = b.country
  AND a.lat = b.lat
  AND a.lon = b.lon
  AND a.device = b.device
  AND a.resource = b.resource
  AND a.severity = b.severity;

-- Natural key for an event: the same identity, timestamp, type, and every
-- other recorded detail. Ingest upserts against this with ON CONFLICT DO
-- NOTHING, mirroring the idempotent-upsert treatment identities/permissions
-- already get, so replaying a source file cannot double-count events.
CREATE UNIQUE INDEX IF NOT EXISTS events_natural_key ON events
    (identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource, severity);

CREATE TABLE IF NOT EXISTS permissions (
    id          BIGSERIAL PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    admin       BOOLEAN NOT NULL DEFAULT FALSE,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (identity_id, name)
);

-- Generated remediation recommendations (right-size / rotation), so the dashboard
-- and API can serve them from the persisted graph rather than recomputing.
CREATE TABLE IF NOT EXISTS remediations (
    id          BIGSERIAL PRIMARY KEY,
    identity_id TEXT NOT NULL,
    kind        TEXT NOT NULL,
    explanation TEXT NOT NULL DEFAULT '',
    code        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (identity_id, kind)
);

CREATE INDEX IF NOT EXISTS remediations_identity ON remediations (identity_id);
