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
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &PgStore{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
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
			`INSERT INTO events (identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			e.IdentityID, e.Time, string(e.Type), e.Outcome,
			e.IP, e.City, e.Country, e.Lat, e.Lon, e.Device, e.Resource); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}
	return tx.Commit()
}

// IngestIdentities writes fully-described identities and their permissions to the database.
// To handle the recursive self-reference on on_behalf_of, we insert/upsert the base
// identity fields first without setting on_behalf_of, then update on_behalf_of in a
// second pass. This avoids foreign key constraint issues if parent agents aren't created yet.
func (s *PgStore) IngestIdentities(ctx context.Context, identities []model.Identity) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Pass 1: Upsert identities without on_behalf_of to establish the rows.
	for _, id := range identities {
		var createdVal, lastUsedVal any
		if !id.Created.IsZero() {
			createdVal = id.Created
		}
		if !id.LastUsed.IsZero() {
			lastUsedVal = id.LastUsed
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO identities (id, privileged, type, source, owner, created, last_used, runtime)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (id) DO UPDATE SET 
			 	privileged = identities.privileged OR EXCLUDED.privileged,
			 	type = CASE WHEN EXCLUDED.type <> '' THEN EXCLUDED.type ELSE identities.type END,
			 	source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE identities.source END,
			 	owner = CASE WHEN EXCLUDED.owner <> '' THEN EXCLUDED.owner ELSE identities.owner END,
			 	created = COALESCE(EXCLUDED.created, identities.created),
			 	last_used = CASE WHEN EXCLUDED.last_used > identities.last_used OR identities.last_used IS NULL THEN EXCLUDED.last_used ELSE identities.last_used END,
			 	runtime = CASE WHEN EXCLUDED.runtime <> '' THEN EXCLUDED.runtime ELSE identities.runtime END`,
			id.ID, id.Privileged, string(id.Type), id.Source, id.Owner, createdVal, lastUsedVal, id.Runtime); err != nil {
			return fmt.Errorf("upsert identity %q: %w", id.ID, err)
		}

		// Delete existing permissions and insert the new ones.
		if _, err := tx.ExecContext(ctx, "DELETE FROM permissions WHERE identity_id = $1", id.ID); err != nil {
			return fmt.Errorf("clear permissions for %q: %w", id.ID, err)
		}
		for _, p := range id.Permissions {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO permissions (identity_id, name, admin, used)
				 VALUES ($1, $2, $3, $4)
				 ON CONFLICT (identity_id, name) DO UPDATE SET admin = EXCLUDED.admin, used = EXCLUDED.used`,
				id.ID, p.Name, p.Admin, p.Used); err != nil {
				return fmt.Errorf("insert permission %q for %q: %w", p.Name, id.ID, err)
			}
		}
	}

	// Pass 2: Update on_behalf_of values now that all identities are present.
	for _, id := range identities {
		if id.OnBehalfOf != "" {
			if _, err := tx.ExecContext(ctx,
				`UPDATE identities SET on_behalf_of = $1 WHERE id = $2`,
				id.OnBehalfOf, id.ID); err != nil {
				return fmt.Errorf("update on_behalf_of for %q: %w", id.ID, err)
			}
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

	// Retrieve all full identities (including NHIs, agents, and delegation chains)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, source, owner, created, last_used, runtime, on_behalf_of, privileged
		 FROM identities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id model.Identity
		var typStr string
		var createdVal, lastUsedVal sql.NullTime
		var onBehalfOfVal sql.NullString
		if err := rows.Scan(&id.ID, &typStr, &id.Source, &id.Owner, &createdVal, &lastUsedVal, &id.Runtime, &onBehalfOfVal, &id.Privileged); err != nil {
			return nil, err
		}
		id.Type = model.IdentityType(typStr)
		if createdVal.Valid {
			id.Created = createdVal.Time
		}
		if lastUsedVal.Valid {
			id.LastUsed = lastUsedVal.Time
		}
		if onBehalfOfVal.Valid {
			id.OnBehalfOf = onBehalfOfVal.String
		}
		store.AddIdentity(id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Retrieve all permissions and attach them to their identities in the store
	permRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, name, admin, used FROM permissions`)
	if err != nil {
		return nil, err
	}
	defer permRows.Close()
	for permRows.Next() {
		var identityID string
		var p model.Permission
		if err := permRows.Scan(&identityID, &p.Name, &p.Admin, &p.Used); err != nil {
			return nil, err
		}
		if idNode := store.ensure(identityID); idNode != nil {
			idNode.Permissions = append(idNode.Permissions, p)
		}
	}
	if err := permRows.Err(); err != nil {
		return nil, err
	}

	// Retrieve all events and attach them
	evRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource
		 FROM events ORDER BY identity_id, ts`)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	for evRows.Next() {
		var e model.Event
		var typ string
		if err := evRows.Scan(&e.IdentityID, &e.Time, &typ, &e.Outcome,
			&e.IP, &e.City, &e.Country, &e.Lat, &e.Lon, &e.Device, &e.Resource); err != nil {
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
