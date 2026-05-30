package graph

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/TAIPANBOX/idryx/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
)

//go:embed schema.sql
var schema string

// PgStore is a Postgres-backed persistence layer for the identity graph. It is
// the durable counterpart to the in-memory Store: Ingest writes events,
// Snapshot reads them all back into an in-memory Store, which implements Reader.
// Detectors therefore run unchanged against either backend.
type PgStore struct {
	db *sql.DB
}

// OpenPg opens a Postgres connection using the pgx driver, verifies it, and
// applies the schema. The DSN is a standard Postgres URL or key/value string.
func OpenPg(ctx context.Context, dsn string) (*PgStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PgStore{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying connection pool.
func (s *PgStore) Close() error { return s.db.Close() }

func (s *PgStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// Ingest writes events and the privileged flags in a single transaction.
// Identities are upserted; the privileged flag is updated when the set marks
// them so re-ingesting with an updated set is idempotent.
func (s *PgStore) Ingest(ctx context.Context, events []model.Event, privileged map[string]bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	seen := map[string]bool{}
	for _, e := range events {
		if !seen[e.IdentityID] {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO identities (id, privileged) VALUES ($1, $2)
				 ON CONFLICT (id) DO UPDATE SET privileged = identities.privileged OR EXCLUDED.privileged`,
				e.IdentityID, privileged[e.IdentityID]); err != nil {
				return fmt.Errorf("upsert identity %q: %w", e.IdentityID, err)
			}
			seen[e.IdentityID] = true
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events (identity_id, ts, type, outcome, ip, city, country, lat, lon, device)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			e.IdentityID, e.Time, string(e.Type), e.Outcome,
			e.IP, e.City, e.Country, e.Lat, e.Lon, e.Device); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}
	return tx.Commit()
}

// Snapshot reads the whole graph into an in-memory Store. The Store sorts events
// chronologically and implements Reader, so detectors consume it unchanged.
func (s *PgStore) Snapshot(ctx context.Context) (*Store, error) {
	priv := map[string]bool{}
	idRows, err := s.db.QueryContext(ctx, `SELECT id, privileged FROM identities`)
	if err != nil {
		return nil, err
	}
	defer idRows.Close()
	for idRows.Next() {
		var id string
		var p bool
		if err := idRows.Scan(&id, &p); err != nil {
			return nil, err
		}
		if p {
			priv[id] = true
		}
	}
	if err := idRows.Err(); err != nil {
		return nil, err
	}

	store := New(priv)
	evRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, ts, type, outcome, ip, city, country, lat, lon, device
		 FROM events ORDER BY identity_id, ts`)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	for evRows.Next() {
		var e model.Event
		var typ string
		if err := evRows.Scan(&e.IdentityID, &e.Time, &typ, &e.Outcome,
			&e.IP, &e.City, &e.Country, &e.Lat, &e.Lon, &e.Device); err != nil {
			return nil, err
		}
		e.Type = model.EventType(typ)
		store.AddEvent(e)
	}
	if err := evRows.Err(); err != nil {
		return nil, err
	}
	return store, nil
}
