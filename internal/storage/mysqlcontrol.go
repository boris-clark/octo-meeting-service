package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// ParticipantRole implements repo.Store.
func (s *MySQLStore) ParticipantRole(ctx context.Context, meetingID, uid string) (string, bool, error) {
	var host string
	err := s.db.QueryRowContext(ctx, `SELECT host_uid FROM meeting WHERE meeting_id = ? AND deleted_at IS NULL`, meetingID).Scan(&host)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("participant role: meeting: %w", err)
	}
	if host == uid {
		return "H", true, nil
	}
	var role string
	err = s.db.QueryRowContext(ctx, `SELECT role FROM meeting_participant WHERE meeting_id = ? AND uid = ?`, meetingID, uid).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("participant role: %w", err)
	}
	return role, true, nil
}

// lockAndCheck loads the meeting FOR UPDATE inside tx and enforces the optimistic
// version (0 = no check).
func lockAndCheckVersion(ctx context.Context, tx *sql.Tx, meetingID string, ifMatch int64) (meeting.Status, int64, error) {
	var status string
	var version int64
	err := tx.QueryRowContext(ctx, `SELECT status, version FROM meeting WHERE meeting_id = ? FOR UPDATE`, meetingID).Scan(&status, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, repo.ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	if ifMatch != 0 && version != ifMatch {
		return "", 0, repo.ErrVersionConflict
	}
	return meeting.Status(status), version, nil
}

// Transition implements repo.Store.
func (s *MySQLStore) Transition(ctx context.Context, meetingID string, to meeting.Status, endReason string, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		status, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch)
		if err != nil {
			return err
		}
		if status == to {
			return nil // idempotent
		}
		if !meeting.CanTransition(status, to) {
			return repo.ErrInvalidTransition
		}
		switch to {
		case meeting.StatusCancelled:
			_, err = tx.ExecContext(ctx, `UPDATE meeting SET status='cancelled', cancelled_at=CURRENT_TIMESTAMP(3), version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, meetingID)
		case meeting.StatusEnded:
			_, err = tx.ExecContext(ctx, `UPDATE meeting SET status='ended', ended_at=CURRENT_TIMESTAMP(3), end_reason=?, version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, endReason, meetingID)
		default:
			return repo.ErrInvalidTransition
		}
		return err
	})
}

// SetLock implements repo.Store.
func (s *MySQLStore) SetLock(ctx context.Context, meetingID string, locked bool, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		if _, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE meeting SET locked=?, version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, locked, meetingID)
		return err
	})
}

// SetRole implements repo.Store.
func (s *MySQLStore) SetRole(ctx context.Context, meetingID, uid, role string, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		if _, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO meeting_participant (meeting_id, uid, role, aggregate_state)
			 VALUES (?, ?, ?, 'joined')
			 ON DUPLICATE KEY UPDATE role=VALUES(role), version=version+1, updated_at=CURRENT_TIMESTAMP(3)`,
			meetingID, uid, role); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE meeting SET version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, meetingID)
		return err
	})
}

// Remove implements repo.Store: a row-locked, version-checked terminal removal
// that bumps the meeting version.
func (s *MySQLStore) Remove(ctx context.Context, meetingID, uid string, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		if _, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO meeting_participant (meeting_id, uid, role, aggregate_state, removed, removed_at)
			 VALUES (?, ?, 'M', 'removed', 1, CURRENT_TIMESTAMP(3))
			 ON DUPLICATE KEY UPDATE aggregate_state='removed', removed=1, removed_at=CURRENT_TIMESTAMP(3), version=version+1, updated_at=CURRENT_TIMESTAMP(3)`,
			meetingID, uid); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE meeting SET version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, meetingID)
		return err
	})
}

// AcquireShare implements repo.Store: row-locked, version-checked single-holder
// acquisition.
func (s *MySQLStore) AcquireShare(ctx context.Context, meetingID, uid, segmentID string, ifMatch int64) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("acquire share: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var (
		holder  sql.NullString
		version int64
	)
	if err := tx.QueryRowContext(ctx, `SELECT share_holder_uid, version FROM meeting WHERE meeting_id = ? FOR UPDATE`, meetingID).Scan(&holder, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, repo.ErrNotFound
		}
		return "", false, fmt.Errorf("acquire share: lock: %w", err)
	}
	if ifMatch != 0 && version != ifMatch {
		return "", false, repo.ErrVersionConflict
	}
	if holder.Valid && holder.String != "" && holder.String != uid {
		return holder.String, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE meeting SET share_holder_uid=?, share_segment_id=?, version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, uid, segmentID, meetingID); err != nil {
		return "", false, fmt.Errorf("acquire share: update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", false, fmt.Errorf("acquire share: commit: %w", err)
	}
	committed = true
	return uid, true, nil
}

// ReleaseShare implements repo.Store: clears the slot only if the current holder
// still equals expectedHolder, under a row-locked version check.
func (s *MySQLStore) ReleaseShare(ctx context.Context, meetingID, expectedHolder string, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		if _, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch); err != nil {
			return err
		}
		var holder sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT share_holder_uid FROM meeting WHERE meeting_id = ?`, meetingID).Scan(&holder); err != nil {
			return err
		}
		if holder.String != expectedHolder {
			return repo.ErrVersionConflict // holder changed between check and update
		}
		_, err := tx.ExecContext(ctx, `UPDATE meeting SET share_holder_uid=NULL, share_segment_id=NULL, version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, meetingID)
		return err
	})
}

// ShareHolder implements repo.Store.
func (s *MySQLStore) ShareHolder(ctx context.Context, meetingID string) (string, error) {
	var holder sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT share_holder_uid FROM meeting WHERE meeting_id = ?`, meetingID).Scan(&holder)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("share holder: %w", err)
	}
	return holder.String, nil
}

// inTx runs fn in a transaction and reloads the meeting record on success.
func (s *MySQLStore) inTx(ctx context.Context, meetingID string, fn func(tx *sql.Tx) error) (repo.Meeting, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return repo.Meeting{}, fmt.Errorf("control tx: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return repo.Meeting{}, err
	}
	m, err := scanMeeting(tx.QueryRowContext(ctx, `SELECT `+meetingColumns("")+` FROM meeting WHERE meeting_id = ?`, meetingID))
	if err != nil {
		return repo.Meeting{}, fmt.Errorf("control tx: reload: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return repo.Meeting{}, fmt.Errorf("control tx: commit: %w", err)
	}
	committed = true
	return m, nil
}

// EditScheduled implements repo.Store. It applies topic/time/duration and/or a
// before-live password change to a scheduled meeting inside a row-locked
// transaction under the optimistic version check.
func (s *MySQLStore) EditScheduled(ctx context.Context, meetingID string, in repo.EditInput, ifMatch int64) (repo.Meeting, error) {
	return s.inTx(ctx, meetingID, func(tx *sql.Tx) error {
		status, _, err := lockAndCheckVersion(ctx, tx, meetingID, ifMatch)
		if err != nil {
			return err
		}
		if status != meeting.StatusScheduled {
			return repo.ErrInvalidTransition
		}
		if in.Topic != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE meeting SET topic=? WHERE meeting_id=?`, *in.Topic, meetingID); err != nil {
				return err
			}
		}
		if in.ScheduledStart != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE meeting SET scheduled_start_at=? WHERE meeting_id=?`, in.ScheduledStart.UTC(), meetingID); err != nil {
				return err
			}
		}
		if in.DurationMinutes != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE meeting SET duration_minutes=? WHERE meeting_id=?`, *in.DurationMinutes, meetingID); err != nil {
				return err
			}
		}
		if in.Password != nil {
			if err := applyPasswordOp(ctx, tx, meetingID, in.Password); err != nil {
				return err
			}
		}
		// Single version bump for the whole edit.
		_, err = tx.ExecContext(ctx, `UPDATE meeting SET version=version+1, updated_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=?`, meetingID)
		return err
	})
}

// applyPasswordOp enables/disables the meeting password before live: a clear
// retires the active verifier and disables the password; a set retires any
// active verifier, inserts the new one, and enables the password.
func applyPasswordOp(ctx context.Context, tx *sql.Tx, meetingID string, op *repo.PasswordOp) error {
	if _, err := tx.ExecContext(ctx, `UPDATE meeting_password_verifier SET status='retired', retired_at=CURRENT_TIMESTAMP(3) WHERE meeting_id=? AND status='active'`, meetingID); err != nil {
		return err
	}
	if op.Clear {
		_, err := tx.ExecContext(ctx, `UPDATE meeting SET password_enabled=0 WHERE meeting_id=?`, meetingID)
		return err
	}
	if op.Verifier == nil {
		return fmt.Errorf("edit: password set without verifier")
	}
	v := op.Verifier
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meeting_password_verifier (meeting_id, algorithm, params_json, salt_id, pepper_ref, verifier, status, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', 'edit')`,
		meetingID, v.Algorithm, v.ParamsJSON, v.SaltID, v.PepperRef, []byte(v.Verifier)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE meeting SET password_enabled=1 WHERE meeting_id=?`, meetingID)
	return err
}
