CREATE TABLE IF NOT EXISTS identities (
    id           TEXT PRIMARY KEY,
    privileged   BOOLEAN NOT NULL DEFAULT FALSE,
    type         TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    owner        TEXT NOT NULL DEFAULT '',
    created      TIMESTAMPTZ,
    last_used    TIMESTAMPTZ,
    runtime      TEXT NOT NULL DEFAULT '',
    on_behalf_of TEXT REFERENCES identities(id) ON DELETE SET NULL
);

-- Ensure existing database instances are migrated if they only have the Phase 0/1 columns.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS created TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_used TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS runtime TEXT NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS on_behalf_of TEXT REFERENCES identities(id) ON DELETE SET NULL;

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
    resource    TEXT NOT NULL DEFAULT ''
);

-- Ensure existing event tables have the resource column for shadow_ai
ALTER TABLE events ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS events_identity_ts ON events (identity_id, ts);

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
