package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// MySQLReadStore is the MySQL-backed implementation of repo.MeetingReadStore. It
// serves the read-only list/detail projection over the existing meeting domain
// schema (no new tables). Visibility is enforced in SQL from the trusted
// principal (space + relationship); it never reads client-supplied identity.
// Raw credential material is never selected in the clear — only the at-rest
// display ciphertexts, which the handler opens for an authorized viewer.
type MySQLReadStore struct {
	db *sql.DB
}

// NewMySQLReadStore builds a read store over the given database handle.
func NewMySQLReadStore(db *sql.DB) *MySQLReadStore {
	return &MySQLReadStore{db: db}
}

// viewSort returns the per-view status set and the COALESCE ordering expression.
// The status literals are fixed constants (no injection surface).
func viewSort(view repo.MeetingListView) (statuses, sortExpr, dir, keysetCmp string) {
	switch view {
	case repo.ViewHistory:
		return "'ended','cancelled'",
			"COALESCE(m.ended_at, m.cancelled_at, m.scheduled_start_at, m.updated_at)",
			"DESC", "<"
	default: // ViewUpcoming
		return "'scheduled','live'",
			"COALESCE(m.scheduled_start_at, m.actual_start_at, m.created_at)",
			"ASC", ">"
	}
}

// ListVisibleMeetings implements repo.MeetingReadStore.
func (s *MySQLReadStore) ListVisibleMeetings(ctx context.Context, spaceID, uid string, view repo.MeetingListView, page repo.Page) (repo.MeetingListPage, error) {
	statuses, sortExpr, dir, cmp := viewSort(view)
	size := repo.ClampPageSize(page.Size)

	// Base visibility: same Space AND the caller is creator/host/invitee/
	// participant. The relationship predicate prevents cross-user leakage even
	// within a Space.
	query := `SELECT m.id, m.meeting_id, m.type, m.status, m.topic,
			m.scheduled_start_at, m.duration_minutes, m.actual_start_at,
			m.ended_at, m.cancelled_at, m.end_reason, m.locked, m.password_enabled, m.version,
			` + sortExpr + ` AS sort_ts,
			EXISTS(SELECT 1 FROM meeting_credential c WHERE c.meeting_id = m.meeting_id AND c.status = 'active') AS join_link_available
		FROM meeting m
		WHERE m.deleted_at IS NULL
			AND m.space_id = ?
			AND m.status IN (` + statuses + `)
			AND ( m.creator_uid = ? OR m.host_uid = ?
				OR EXISTS(SELECT 1 FROM meeting_invite i WHERE i.meeting_id = m.meeting_id AND i.invitee_uid = ? AND i.status = 'invited')
				OR EXISTS(SELECT 1 FROM meeting_participant p WHERE p.meeting_id = m.meeting_id AND p.uid = ?) )`

	args := []any{spaceID, uid, uid, uid, uid}

	// Keyset cursor: keep rows strictly after the cursor position under the view's
	// sort direction, with the internal id as a stable tie-breaker.
	if page.Token != "" {
		if ts, id, ok := repo.DecodeCursor(page.Token, view); ok {
			query += ` AND (` + sortExpr + ` ` + cmp + ` ? OR (` + sortExpr + ` = ? AND m.id ` + cmp + ` ?))`
			args = append(args, ts, ts, id)
		}
	}

	query += ` ORDER BY sort_ts ` + dir + `, m.id ` + dir + ` LIMIT ?`
	args = append(args, size+1) // fetch one extra to detect a following page

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return repo.MeetingListPage{}, fmt.Errorf("list meetings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := repo.MeetingListPage{Items: make([]repo.MeetingSummary, 0, size)}
	var (
		lastKey time.Time
		lastID  int64
		count   int
	)
	for rows.Next() {
		var (
			id     int64
			sum    repo.MeetingSummary
			sortTS sql.NullTime
			joinAv int
		)
		if err := scanSummary(rows, &id, &sum, &sortTS, &joinAv); err != nil {
			return repo.MeetingListPage{}, err
		}
		sum.JoinLinkAvailable = joinAv == 1
		count++
		if count > size {
			// The extra row confirms another page; emit a cursor from the last kept
			// row rather than exposing this one.
			out.NextPageToken = repo.EncodeCursor(view, lastKey, lastID)
			break
		}
		out.Items = append(out.Items, sum)
		if sortTS.Valid {
			lastKey = sortTS.Time.UTC()
		}
		lastID = id
	}
	if err := rows.Err(); err != nil {
		return repo.MeetingListPage{}, fmt.Errorf("list meetings: %w", err)
	}
	return out, nil
}

// scanSummary reads one list row (shared column order) into a MeetingSummary.
func scanSummary(rows *sql.Rows, id *int64, sum *repo.MeetingSummary, sortTS *sql.NullTime, joinAv *int) error {
	var (
		typ, status string
		topic       sql.NullString
		sched       sql.NullTime
		dur         sql.NullInt64
		actual      sql.NullTime
		ended       sql.NullTime
		cancelled   sql.NullTime
		endReason   sql.NullString
	)
	if err := rows.Scan(
		id, &sum.MeetingID, &typ, &status, &topic,
		&sched, &dur, &actual, &ended, &cancelled, &endReason,
		&sum.Locked, &sum.PasswordEnabled, &sum.Version, sortTS, joinAv,
	); err != nil {
		return fmt.Errorf("scan meeting summary: %w", err)
	}
	sum.Type = meeting.Type(typ)
	sum.Status = meeting.Status(status)
	sum.Topic = topic.String
	if sched.Valid {
		sum.ScheduledStartAt = sched.Time.UTC()
	}
	if dur.Valid {
		sum.DurationMinutes = int(dur.Int64)
	}
	if actual.Valid {
		sum.ActualStartAt = actual.Time.UTC()
	}
	if ended.Valid {
		sum.EndedAt = ended.Time.UTC()
	}
	if cancelled.Valid {
		sum.CancelledAt = cancelled.Time.UTC()
	}
	sum.EndReason = endReason.String
	return nil
}

// GetMeetingDetail implements repo.MeetingReadStore.
func (s *MySQLReadStore) GetMeetingDetail(ctx context.Context, meetingID string) (repo.MeetingDetail, bool, error) {
	const q = `SELECT meeting_id, space_id, type, status, topic, scheduled_start_at,
			duration_minutes, actual_start_at, ended_at, cancelled_at, end_reason,
			locked, password_enabled, creator_uid, host_uid, version
		FROM meeting WHERE meeting_id = ? AND deleted_at IS NULL`

	var (
		d           repo.MeetingDetail
		typ, status string
		topic       sql.NullString
		sched       sql.NullTime
		dur         sql.NullInt64
		actual      sql.NullTime
		ended       sql.NullTime
		cancelled   sql.NullTime
		endReason   sql.NullString
	)
	err := s.db.QueryRowContext(ctx, q, meetingID).Scan(
		&d.Summary.MeetingID, &d.SpaceID, &typ, &status, &topic, &sched,
		&dur, &actual, &ended, &cancelled, &endReason,
		&d.Summary.Locked, &d.Summary.PasswordEnabled, &d.CreatorUID, &d.HostUID, &d.Summary.Version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return repo.MeetingDetail{}, false, nil
	}
	if err != nil {
		return repo.MeetingDetail{}, false, fmt.Errorf("get meeting: %w", err)
	}
	d.Summary.Type = meeting.Type(typ)
	d.Summary.Status = meeting.Status(status)
	d.Summary.Topic = topic.String
	if sched.Valid {
		d.Summary.ScheduledStartAt = sched.Time.UTC()
	}
	if dur.Valid {
		d.Summary.DurationMinutes = int(dur.Int64)
	}
	if actual.Valid {
		d.Summary.ActualStartAt = actual.Time.UTC()
	}
	if ended.Valid {
		d.Summary.EndedAt = ended.Time.UTC()
	}
	if cancelled.Valid {
		d.Summary.CancelledAt = cancelled.Time.UTC()
	}
	d.Summary.EndReason = endReason.String

	// Credential display ciphertexts (never selected in the clear). Their presence
	// also drives join_link_available.
	credErr := s.db.QueryRowContext(ctx,
		`SELECT number_display_ciphertext, link_token_ciphertext FROM meeting_credential
			WHERE meeting_id = ? AND status = 'active' LIMIT 1`, meetingID).
		Scan(&d.NumberCipher, &d.LinkCipher)
	switch {
	case errors.Is(credErr, sql.ErrNoRows):
		d.Summary.JoinLinkAvailable = false
	case credErr != nil:
		return repo.MeetingDetail{}, false, fmt.Errorf("get meeting credential: %w", credErr)
	default:
		d.Summary.JoinLinkAvailable = len(d.LinkCipher) > 0
	}

	if d.Participants, err = s.loadParticipants(ctx, meetingID); err != nil {
		return repo.MeetingDetail{}, false, err
	}
	if d.Invites, err = s.loadInvites(ctx, meetingID); err != nil {
		return repo.MeetingDetail{}, false, err
	}
	return d, true, nil
}

func (s *MySQLReadStore) loadParticipants(ctx context.Context, meetingID string) ([]repo.MeetingParticipant, error) {
	const q = `SELECT uid, role, aggregate_state, removed, first_joined_at, last_left_at, version
		FROM meeting_participant WHERE meeting_id = ? ORDER BY first_joined_at IS NULL, first_joined_at ASC, uid ASC`
	rows, err := s.db.QueryContext(ctx, q, meetingID)
	if err != nil {
		return nil, fmt.Errorf("load participants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []repo.MeetingParticipant
	for rows.Next() {
		var (
			p         repo.MeetingParticipant
			firstJoin sql.NullTime
			lastLeft  sql.NullTime
		)
		if err := rows.Scan(&p.UID, &p.Role, &p.AggregateState, &p.Removed, &firstJoin, &lastLeft, &p.Version); err != nil {
			return nil, fmt.Errorf("scan participant: %w", err)
		}
		if firstJoin.Valid {
			p.FirstJoinedAt = firstJoin.Time.UTC()
		}
		if lastLeft.Valid {
			p.LastLeftAt = lastLeft.Time.UTC()
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load participants: %w", err)
	}
	return out, nil
}

func (s *MySQLReadStore) loadInvites(ctx context.Context, meetingID string) ([]repo.MeetingInvite, error) {
	const q = `SELECT invitee_uid, status, invited_by, version
		FROM meeting_invite WHERE meeting_id = ? ORDER BY invitee_uid ASC`
	rows, err := s.db.QueryContext(ctx, q, meetingID)
	if err != nil {
		return nil, fmt.Errorf("load invites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []repo.MeetingInvite
	for rows.Next() {
		var iv repo.MeetingInvite
		if err := rows.Scan(&iv.InviteeUID, &iv.Status, &iv.InvitedBy, &iv.Version); err != nil {
			return nil, fmt.Errorf("scan invite: %w", err)
		}
		out = append(out, iv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load invites: %w", err)
	}
	return out, nil
}
