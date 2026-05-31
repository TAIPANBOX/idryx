package graph

import (
	"context"

	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// SaveRemediations upserts a batch of remediation recommendations, keyed by
// (identity_id, kind) so re-running remediation refreshes rather than duplicates.
// It is a no-op for an empty slice.
func (s *PgStore) SaveRemediations(ctx context.Context, recs []*remediation.Recommendation) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	for _, r := range recs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO remediations (identity_id, kind, explanation, code, created_at)
			 VALUES ($1, $2, $3, $4, now())
			 ON CONFLICT (identity_id, kind) DO UPDATE SET
				explanation = EXCLUDED.explanation,
				code        = EXCLUDED.code,
				created_at  = now()`,
			r.IdentityID, r.Kind, r.Explanation, r.Code); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Remediations returns all persisted recommendations, ordered by identity then
// kind for a stable result.
func (s *PgStore) Remediations(ctx context.Context) ([]*remediation.Recommendation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, kind, explanation, code
		 FROM remediations ORDER BY identity_id, kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*remediation.Recommendation
	for rows.Next() {
		r := &remediation.Recommendation{}
		if err := rows.Scan(&r.IdentityID, &r.Kind, &r.Explanation, &r.Code); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
