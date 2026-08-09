package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/worker"
)

// MySQLJobStore is the durable outbox queue backing the worker dispatcher. It
// claims due, ready rows with FOR UPDATE SKIP LOCKED so multiple workers do not
// double-deliver, and persists the retry/dead-letter outcome. Delivery is
// idempotent: sent rows are never re-claimed and rows are deduped by dedupe_key
// at enqueue time.
type MySQLJobStore struct {
	db *sql.DB
}

// NewMySQLJobStore builds the store.
func NewMySQLJobStore(db *sql.DB) *MySQLJobStore { return &MySQLJobStore{db: db} }

// ClaimDue leases up to limit due, ready outbox rows to owner.
func (s *MySQLJobStore) ClaimDue(ctx context.Context, now time.Time, owner string, limit int) ([]worker.Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("claim due: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx,
		`SELECT id, recipient_uid, event_type, payload_redacted_json, attempt_count
		   FROM meeting_outbox
		  WHERE status IN ('pending','failed')
		    AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		    AND (lease_until IS NULL OR lease_until <= ?)
		  ORDER BY id
		  LIMIT ?
		  FOR UPDATE SKIP LOCKED`,
		now.UTC(), now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("claim due: select: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		jobs []worker.Job
		ids  []any
	)
	for rows.Next() {
		var (
			id           int64
			recipient    sql.NullString
			eventType    string
			payloadJSON  []byte
			attemptCount int
		)
		if err := rows.Scan(&id, &recipient, &eventType, &payloadJSON, &attemptCount); err != nil {
			return nil, fmt.Errorf("claim due: scan: %w", err)
		}
		payload := map[string]any{}
		if len(payloadJSON) > 0 {
			_ = json.Unmarshal(payloadJSON, &payload)
		}
		jobs = append(jobs, worker.Job{
			ID: fmt.Sprintf("%d", id), RecipientUID: recipient.String,
			Template: eventType, Payload: payload, AttemptCount: attemptCount,
		})
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("claim due: rows: %w", err)
	}

	leaseUntil := now.Add(30 * time.Second).UTC()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE meeting_outbox SET status='leased', lease_owner=?, lease_until=?, updated_at=CURRENT_TIMESTAMP(3) WHERE id=?`,
			owner, leaseUntil, id); err != nil {
			return nil, fmt.Errorf("claim due: lease: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("claim due: commit: %w", err)
	}
	committed = true
	return jobs, nil
}

// MarkSent implements worker.JobStore.
func (s *MySQLJobStore) MarkSent(ctx context.Context, jobID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE meeting_outbox SET status='sent', lease_owner=NULL, lease_until=NULL, updated_at=CURRENT_TIMESTAMP(3) WHERE id=?`, jobID)
	if err != nil {
		return fmt.Errorf("mark sent: %w", err)
	}
	return nil
}

// Reschedule implements worker.JobStore.
func (s *MySQLJobStore) Reschedule(ctx context.Context, jobID string, nextAttemptAt time.Time, attemptCount int, lastErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE meeting_outbox SET status='failed', attempt_count=?, next_attempt_at=?, last_error_code=?,
		    lease_owner=NULL, lease_until=NULL, updated_at=CURRENT_TIMESTAMP(3) WHERE id=?`,
		attemptCount, nextAttemptAt.UTC(), truncErr(lastErr), jobID)
	if err != nil {
		return fmt.Errorf("reschedule: %w", err)
	}
	return nil
}

// MarkDead implements worker.JobStore.
func (s *MySQLJobStore) MarkDead(ctx context.Context, jobID string, lastErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE meeting_outbox SET status='dead', last_error_code=?, lease_owner=NULL, lease_until=NULL, updated_at=CURRENT_TIMESTAMP(3) WHERE id=?`,
		truncErr(lastErr), jobID)
	if err != nil {
		return fmt.Errorf("mark dead: %w", err)
	}
	return nil
}

func truncErr(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

var _ worker.JobStore = (*MySQLJobStore)(nil)
