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

// eventsOrderBy orders Snapshot's events query chronologically per identity,
// with the surrogate id as an explicit tiebreaker. Postgres does not
// guarantee any particular order for rows with equal ts beyond the ORDER BY
// clause given, while the in-memory Store's Identities sorts with
// sort.SliceStable, which preserves append (insertion) order for equal
// timestamps. Without the id tiebreaker here, two events with identical ts
// could order differently across backends (and across repeated snapshots of
// the same data), flipping which one new_device/impossible_travel treats as
// the baseline versus the anomaly. id is BIGSERIAL, so ordering by it
// matches insertion order, the same tiebreak the in-memory Store gives.
const eventsOrderBy = `ORDER BY identity_id, ts, id`

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
			`INSERT INTO events (identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource, severity)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 ON CONFLICT (identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource, severity) DO NOTHING`,
			e.IdentityID, e.Time, string(e.Type), e.Outcome,
			e.IP, e.City, e.Country, e.Lat, e.Lon, e.Device, e.Resource, e.Severity); err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}
	return tx.Commit()
}

// IngestIdentities writes fully-described identities and their permissions to the database.
// To handle the recursive self-reference the delegation chain can create (an
// agent's principal is often another agent row in the same batch), we
// insert/upsert the base identity fields first, then write each identity's
// on_behalf_of chain in a second pass. This avoids ordering issues if a
// principal referenced by ID isn't inserted yet.
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
			`INSERT INTO identities (id, privileged, type, source, owner, created, last_used, runtime, parent, attestation, shadow)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			 ON CONFLICT (id) DO UPDATE SET
			 	privileged = identities.privileged OR EXCLUDED.privileged,
			 	type = CASE WHEN EXCLUDED.type <> '' THEN EXCLUDED.type ELSE identities.type END,
			 	source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE identities.source END,
			 	owner = CASE WHEN EXCLUDED.owner <> '' THEN EXCLUDED.owner ELSE identities.owner END,
			 	created = COALESCE(EXCLUDED.created, identities.created),
			 	last_used = CASE WHEN EXCLUDED.last_used > identities.last_used OR identities.last_used IS NULL THEN EXCLUDED.last_used ELSE identities.last_used END,
			 	runtime = CASE WHEN EXCLUDED.runtime <> '' THEN EXCLUDED.runtime ELSE identities.runtime END,
			 	parent = CASE WHEN EXCLUDED.parent <> '' THEN EXCLUDED.parent ELSE identities.parent END,
			 	attestation = CASE WHEN EXCLUDED.attestation <> '' THEN EXCLUDED.attestation ELSE identities.attestation END,
			 	shadow = identities.shadow OR EXCLUDED.shadow`,
			id.ID, id.Privileged, string(id.Type), id.Source, id.Owner, createdVal, lastUsedVal, id.Runtime, id.Parent, id.Attestation, id.Shadow); err != nil {
			return fmt.Errorf("upsert identity %q: %w", id.ID, err)
		}

		// Delete existing permissions and insert the new ones.
		if _, err := tx.ExecContext(ctx, "DELETE FROM permissions WHERE identity_id = $1", id.ID); err != nil {
			return fmt.Errorf("clear permissions for %q: %w", id.ID, err)
		}
		for _, p := range id.Permissions {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO permissions (identity_id, name, admin, used, arn)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (identity_id, name) DO UPDATE SET admin = EXCLUDED.admin, used = EXCLUDED.used, arn = EXCLUDED.arn`,
				id.ID, p.Name, p.Admin, p.Used, p.ARN); err != nil {
				return fmt.Errorf("insert permission %q for %q: %w", p.Name, id.ID, err)
			}
			// The actions the grant allows (from an AWS policy document or a
			// GCP/Azure role definition). The DELETE above cascades the old
			// rows away; the ON CONFLICT path above does not, so clear them
			// explicitly and rewrite, which keeps a re-ingest idempotent
			// either way.
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM permission_actions WHERE identity_id = $1 AND permission_name = $2",
				id.ID, p.Name); err != nil {
				return fmt.Errorf("clear actions for permission %q of %q: %w", p.Name, id.ID, err)
			}
			for i, action := range p.Actions {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO permission_actions (identity_id, permission_name, position, action) VALUES ($1, $2, $3, $4)`,
					id.ID, p.Name, i, action); err != nil {
					return fmt.Errorf("insert action[%d] for permission %q of %q: %w", i, p.Name, id.ID, err)
				}
			}
		}
	}

	// Pass 2: Write each identity's delegation chain now that all identities
	// are present. Replace-in-place (delete then insert) keeps re-ingestion
	// idempotent, same as the permissions handling above.
	for _, id := range identities {
		if _, err := tx.ExecContext(ctx, "DELETE FROM on_behalf_of WHERE identity_id = $1", id.ID); err != nil {
			return fmt.Errorf("clear on_behalf_of for %q: %w", id.ID, err)
		}
		for i, principal := range id.OnBehalfOf {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO on_behalf_of (identity_id, position, principal) VALUES ($1, $2, $3)`,
				id.ID, i, principal); err != nil {
				return fmt.Errorf("insert on_behalf_of[%d] for %q: %w", i, id.ID, err)
			}
		}

		// The Passport's declared models (SPEC §4.5), same replace-in-place
		// treatment and same reason: a re-ingest must refresh the
		// declaration, never append a second copy of it.
		if _, err := tx.ExecContext(ctx, "DELETE FROM declared_models WHERE identity_id = $1", id.ID); err != nil {
			return fmt.Errorf("clear declared_models for %q: %w", id.ID, err)
		}
		for i, m := range id.DeclaredModels {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO declared_models (identity_id, position, provider, model, endpoint) VALUES ($1, $2, $3, $4, $5)`,
				id.ID, i, m.Provider, m.Model, m.Endpoint); err != nil {
				return fmt.Errorf("insert declared_models[%d] for %q: %w", i, id.ID, err)
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

	// Retrieve all full identities (including NHIs and agents; delegation
	// chains are loaded separately below)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, source, owner, created, last_used, runtime, privileged, parent, attestation, shadow
		 FROM identities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id model.Identity
		var typStr string
		var createdVal, lastUsedVal sql.NullTime
		if err := rows.Scan(&id.ID, &typStr, &id.Source, &id.Owner, &createdVal, &lastUsedVal, &id.Runtime, &id.Privileged, &id.Parent, &id.Attestation, &id.Shadow); err != nil {
			return nil, err
		}
		id.Type = model.IdentityType(typStr)
		if createdVal.Valid {
			id.Created = createdVal.Time
		}
		if lastUsedVal.Valid {
			id.LastUsed = lastUsedVal.Time
		}
		store.AddIdentity(id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Retrieve every identity's delegation chain (agent-passport SPEC §5:
	// ordered root-first) and attach it in position order.
	oboRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, principal FROM on_behalf_of ORDER BY identity_id, position`)
	if err != nil {
		return nil, err
	}
	defer oboRows.Close()
	for oboRows.Next() {
		var identityID, principal string
		if err := oboRows.Scan(&identityID, &principal); err != nil {
			return nil, err
		}
		if idNode := store.ensure(identityID); idNode != nil {
			idNode.OnBehalfOf = append(idNode.OnBehalfOf, principal)
		}
	}
	if err := oboRows.Err(); err != nil {
		return nil, err
	}

	// Retrieve every agent's Passport-declared models (SPEC §4.5) in
	// declaration order. Without this the undeclared_llm detector saw an
	// empty declaration on every agent over --db and skipped all of them,
	// which reads exactly like an estate with no drift.
	dmRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, provider, model, endpoint FROM declared_models ORDER BY identity_id, position`)
	if err != nil {
		return nil, err
	}
	defer dmRows.Close()
	for dmRows.Next() {
		var identityID string
		var m model.DeclaredModel
		if err := dmRows.Scan(&identityID, &m.Provider, &m.Model, &m.Endpoint); err != nil {
			return nil, err
		}
		if idNode := store.ensure(identityID); idNode != nil {
			idNode.DeclaredModels = append(idNode.DeclaredModels, m)
		}
	}
	if err := dmRows.Err(); err != nil {
		return nil, err
	}

	// Retrieve the actions each grant allows BEFORE the permissions
	// themselves, so each Permission can be built complete: Permissions is a
	// slice, and appending to it moves the elements, so there is nothing
	// stable to attach to afterwards.
	actionsByPerm := map[string]map[string][]string{}
	actRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, permission_name, action FROM permission_actions ORDER BY identity_id, permission_name, position`)
	if err != nil {
		return nil, err
	}
	defer actRows.Close()
	for actRows.Next() {
		var identityID, permName, action string
		if err := actRows.Scan(&identityID, &permName, &action); err != nil {
			return nil, err
		}
		if actionsByPerm[identityID] == nil {
			actionsByPerm[identityID] = map[string][]string{}
		}
		actionsByPerm[identityID][permName] = append(actionsByPerm[identityID][permName], action)
	}
	if err := actRows.Err(); err != nil {
		return nil, err
	}

	// Retrieve all permissions and attach them to their identities in the store
	permRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, name, admin, used, arn FROM permissions`)
	if err != nil {
		return nil, err
	}
	defer permRows.Close()
	for permRows.Next() {
		var identityID string
		var p model.Permission
		if err := permRows.Scan(&identityID, &p.Name, &p.Admin, &p.Used, &p.ARN); err != nil {
			return nil, err
		}
		p.Actions = actionsByPerm[identityID][p.Name]
		if idNode := store.ensure(identityID); idNode != nil {
			idNode.Permissions = append(idNode.Permissions, p)
		}
	}
	if err := permRows.Err(); err != nil {
		return nil, err
	}

	// Retrieve all events and attach them
	evRows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, ts, type, outcome, ip, city, country, lat, lon, device, resource, severity
		 FROM events `+eventsOrderBy)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	for evRows.Next() {
		var e model.Event
		var typ string
		if err := evRows.Scan(&e.IdentityID, &e.Time, &typ, &e.Outcome,
			&e.IP, &e.City, &e.Country, &e.Lat, &e.Lon, &e.Device, &e.Resource, &e.Severity); err != nil {
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
