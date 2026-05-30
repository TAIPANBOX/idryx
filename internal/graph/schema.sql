CREATE TABLE IF NOT EXISTS identities (
    id         TEXT PRIMARY KEY,
    privileged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    ts          TIMESTAMPTZ NOT NULL,
    type        TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    city        TEXT NOT NULL DEFAULT '',
    country     TEXT NOT NULL DEFAULT '',
    lat         DOUBLE PRECISION NOT NULL DEFAULT 0,
    lon         DOUBLE PRECISION NOT NULL DEFAULT 0,
    device      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS events_identity_ts ON events (identity_id, ts);
