package graph

import (
	"context"
	"time"

	"github.com/TAIPANBOX/idryx/internal/remediation"
)

// StoredRemediation pairs a persisted recommendation with the time it was
// written, so consumers can show the age of a recommendation. CreatedAt is a
// persistence concern and deliberately lives here, not on the core
// remediation.Recommendation type.
type StoredRemediation struct {
	Recommendation *remediation.Recommendation
	CreatedAt      time.Time
}

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

// RemediationRecords returns all persisted recommendations with their stored
// timestamps, ordered by identity then kind for a stable result.
func (s *PgStore) RemediationRecords(ctx context.Context) ([]StoredRemediation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT identity_id, kind, explanation, code, created_at
		 FROM remediations ORDER BY identity_id, kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []StoredRemediation
	for rows.Next() {
		r := &remediation.Recommendation{}
		var created time.Time
		if err := rows.Scan(&r.IdentityID, &r.Kind, &r.Explanation, &r.Code, &created); err != nil {
			return nil, err
		}
		out = append(out, StoredRemediation{Recommendation: r, CreatedAt: created})
	}
	return out, rows.Err()
}

// Remediations returns all persisted recommendations (without timestamps),
// ordered by identity then kind.
func (s *PgStore) Remediations(ctx context.Context) ([]*remediation.Recommendation, error) {
	records, err := s.RemediationRecords(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*remediation.Recommendation, 0, len(records))
	for _, rec := range records {
		out = append(out, rec.Recommendation)
	}
	return out, nil
}
