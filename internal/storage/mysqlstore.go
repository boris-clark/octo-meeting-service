package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// MySQLStore is the MySQL-backed implementation of repo.Store. All queries are
// parameterized. Credential resolution by meeting number / link token uses an
// HMAC lookup hash so the raw credential is never used as an index or stored in
// the clear. The DSN must enable time parsing (parseTime=true&loc=UTC).
type MySQLStore struct {
	db           *sql.DB
	lookupSecret []byte
}

// NewMySQLStore builds a store. An empty lookupSecret disables number/link
// resolution (those lookups return not-found) rather than computing an
// attacker-influenced hash with a zero key.
func NewMySQLStore(db *sql.DB, lookupSecret string) *MySQLStore {
	return &MySQLStore{db: db, lookupSecret: []byte(lookupSecret)}
}

// meetingSelectCols is the single source of truth for the meeting SELECT list,
// in the exact order scanMeeting reads. meetingColumns renders it optionally
// qualified by a table alias — the joined ByNumber/ByLink queries MUST qualify
// (both meeting and meeting_credential expose meeting_id, so an unqualified list
// is an ambiguous-column error).
var meetingSelectCols = []string{
	"meeting_id", "space_id", "type", "status", "creator_uid", "host_uid",
	"scheduled_start_at", "duration_minutes", "actual_start_at", "password_enabled",
	"locked", "max_participants", "version",
}

func meetingColumns(alias string) string {
	if alias == "" {
		return strings.Join(meetingSelectCols, ", ")
	}
	qualified := make([]string, len(meetingSelectCols))
	for i, c := range meetingSelectCols {
		qualified[i] = alias + "." + c
	}
	return strings.Join(qualified, ", ")
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMeeting(row rowScanner) (repo.Meeting, error) {
	var (
		m            repo.Meeting
		typ, status  string
		schedStart   sql.NullTime
		durationMins sql.NullInt64
		actualStart  sql.NullTime
		passwordEn   bool
		locked       bool
	)
	if err := row.Scan(
		&m.MeetingID, &m.SpaceID, &typ, &status, &m.CreatorUID, &m.HostUID,
		&schedStart, &durationMins, &actualStart, &passwordEn, &locked,
		&m.MaxParticipants, &m.Version,
	); err != nil {
		return repo.Meeting{}, err
	}
	m.Type = meeting.Type(typ)
	m.Status = meeting.Status(status)
	m.PasswordEnabled = passwordEn
	m.Locked = locked
	if schedStart.Valid {
		m.ScheduledStartAt = schedStart.Time.UTC()
	}
	if actualStart.Valid {
		m.ActualStartAt = actualStart.Time.UTC()
	}
	return m, nil
}

// Resolve implements repo.Store.
func (s *MySQLStore) Resolve(ctx context.Context, kind repo.CredentialKind, value string) (repo.Meeting, bool, error) {
	var (
		query string
		arg   any
	)
	switch kind {
	case repo.ByID:
		query = `SELECT ` + meetingColumns("") + ` FROM meeting WHERE meeting_id = ? AND deleted_at IS NULL`
		arg = value
	case repo.ByNumber:
		if len(s.lookupSecret) == 0 {
			return repo.Meeting{}, false, nil
		}
		query = `SELECT ` + meetingColumns("m") + ` FROM meeting m
			JOIN meeting_credential c ON c.meeting_id = m.meeting_id
			WHERE c.number_lookup_hash = ? AND c.status = 'active' AND m.deleted_at IS NULL`
		arg = s.lookupHash(value)
	case repo.ByLink:
		if len(s.lookupSecret) == 0 {
			return repo.Meeting{}, false, nil
		}
		query = `SELECT ` + meetingColumns("m") + ` FROM meeting m
			JOIN meeting_credential c ON c.meeting_id = m.meeting_id
			WHERE c.link_token_lookup_hash = ? AND c.status = 'active' AND m.deleted_at IS NULL`
		arg = s.lookupHash(value)
	default:
		return repo.Meeting{}, false, fmt.Errorf("unknown credential kind %q", kind)
	}

	m, err := scanMeeting(s.db.QueryRowContext(ctx, query, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return repo.Meeting{}, false, nil
	}
	if err != nil {
		return repo.Meeting{}, false, fmt.Errorf("resolve meeting: %w", err)
	}
	return m, true, nil
}

func (s *MySQLStore) lookupHash(value string) []byte {
	mac := hmac.New(sha256.New, s.lookupSecret)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// ActiveParticipantCount implements repo.Store. Active = a segment that has not
// left and has not been superseded (the authoritative full/empty count).
func (s *MySQLStore) ActiveParticipantCount(ctx context.Context, meetingID string) (int, error) {
	const q = `SELECT COUNT(*) FROM meeting_participant_segment
		WHERE meeting_id = ? AND leave_at IS NULL AND superseded_by_segment_id IS NULL`
	var n int
	if err := s.db.QueryRowContext(ctx, q, meetingID).Scan(&n); err != nil {
		return 0, fmt.Errorf("active participant count: %w", err)
	}
	return n, nil
}

// IsRemoved implements repo.Store.
func (s *MySQLStore) IsRemoved(ctx context.Context, meetingID, uid string) (bool, error) {
	const q = `SELECT removed FROM meeting_participant WHERE meeting_id = ? AND uid = ?`
	var removed bool
	err := s.db.QueryRowContext(ctx, q, meetingID, uid).Scan(&removed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is removed: %w", err)
	}
	return removed, nil
}

// IsInvitee implements repo.Store.
func (s *MySQLStore) IsInvitee(ctx context.Context, meetingID, uid string) (bool, error) {
	const q = `SELECT 1 FROM meeting_invite WHERE meeting_id = ? AND invitee_uid = ? AND status = 'invited'`
	return s.exists(ctx, q, meetingID, uid)
}

// IsParticipant implements repo.Store.
func (s *MySQLStore) IsParticipant(ctx context.Context, meetingID, uid string) (bool, error) {
	const q = `SELECT 1 FROM meeting_participant WHERE meeting_id = ? AND uid = ?`
	return s.exists(ctx, q, meetingID, uid)
}

func (s *MySQLStore) exists(ctx context.Context, query string, args ...any) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("exists check: %w", err)
	}
	return true, nil
}

// StartLive implements repo.Store. It atomically transitions a scheduled meeting
// to live on first finalize under a row lock, and is a no-op returning the
// current record when already live.
func (s *MySQLStore) StartLive(ctx context.Context, meetingID string, now time.Time) (repo.Meeting, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return repo.Meeting{}, fmt.Errorf("start live: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM meeting WHERE meeting_id = ? FOR UPDATE`, meetingID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return repo.Meeting{}, repo.ErrNotFound
	}
	if err != nil {
		return repo.Meeting{}, fmt.Errorf("start live: lock: %w", err)
	}

	if meeting.Status(status) == meeting.StatusScheduled {
		const upd = `UPDATE meeting SET status = 'live', actual_start_at = ?, version = version + 1,
			updated_at = CURRENT_TIMESTAMP(3) WHERE meeting_id = ?`
		if _, err := tx.ExecContext(ctx, upd, now.UTC(), meetingID); err != nil {
			return repo.Meeting{}, fmt.Errorf("start live: update: %w", err)
		}
	}

	m, err := scanMeeting(tx.QueryRowContext(ctx, `SELECT `+meetingColumns("")+` FROM meeting WHERE meeting_id = ?`, meetingID))
	if err != nil {
		return repo.Meeting{}, fmt.Errorf("start live: reload: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return repo.Meeting{}, fmt.Errorf("start live: commit: %w", err)
	}
	return m, nil
}

// compile-time assertion.
var _ repo.Store = (*MySQLStore)(nil)

// CreateMeeting implements repo.Store. It persists the meeting, its credential
// (with store-derived HMAC lookup hashes), and an optional password verifier in
// one transaction, guarded by the idempotency key. On replay it returns the
// ORIGINAL persisted credential ciphertexts (loaded from meeting_credential) so
// the handler never echoes freshly-minted, unpersisted credentials.
func (s *MySQLStore) CreateMeeting(ctx context.Context, in repo.CreateInput) (repo.CreateResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return repo.CreateResult{}, fmt.Errorf("create meeting: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if in.IdempotencyKey != "" {
		keyHash := s.lookupHash(in.IdempotencyScope + "|" + in.IdempotencyKey)
		var fingerprint, resultRef string
		err := tx.QueryRowContext(ctx,
			`SELECT payload_fingerprint, result_ref FROM meeting_idempotency_key WHERE scope = ? AND key_hash = ?`,
			in.IdempotencyScope, keyHash).Scan(&fingerprint, &resultRef)
		switch {
		case err == nil:
			if fingerprint != in.PayloadFingerprint {
				return repo.CreateResult{}, repo.ErrIdempotencyConflict
			}
			m, rerr := scanMeeting(tx.QueryRowContext(ctx, `SELECT `+meetingColumns("")+` FROM meeting WHERE meeting_id = ?`, resultRef))
			if rerr != nil {
				return repo.CreateResult{}, fmt.Errorf("create meeting: replay load: %w", rerr)
			}
			var numberCT, linkCT []byte
			if cerr := tx.QueryRowContext(ctx,
				`SELECT number_display_ciphertext, link_token_ciphertext FROM meeting_credential WHERE meeting_id = ?`,
				resultRef).Scan(&numberCT, &linkCT); cerr != nil {
				return repo.CreateResult{}, fmt.Errorf("create meeting: replay credential: %w", cerr)
			}
			if cerr := tx.Commit(); cerr != nil {
				return repo.CreateResult{}, cerr
			}
			committed = true
			return repo.CreateResult{Meeting: m, Replayed: true, NumberCiphertext: numberCT, LinkCiphertext: linkCT}, nil
		case errors.Is(err, sql.ErrNoRows):
			// fall through to insert
		default:
			return repo.CreateResult{}, fmt.Errorf("create meeting: idem lookup: %w", err)
		}
	}

	if err := s.insertMeeting(ctx, tx, in.Meeting); err != nil {
		return repo.CreateResult{}, err
	}
	if err := s.insertCredential(ctx, tx, in); err != nil {
		return repo.CreateResult{}, err
	}
	if in.Verifier != nil {
		if err := s.insertVerifier(ctx, tx, in.Meeting.MeetingID, in.Meeting.CreatorUID, *in.Verifier); err != nil {
			return repo.CreateResult{}, err
		}
	}
	if in.IdempotencyKey != "" {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO meeting_idempotency_key (scope, key_hash, payload_fingerprint, result_ref, expires_at)
			 VALUES (?, ?, ?, ?, DATE_ADD(CURRENT_TIMESTAMP(3), INTERVAL 1 HOUR))`,
			in.IdempotencyScope, s.lookupHash(in.IdempotencyScope+"|"+in.IdempotencyKey), in.PayloadFingerprint, in.Meeting.MeetingID); err != nil {
			return repo.CreateResult{}, fmt.Errorf("create meeting: idem insert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return repo.CreateResult{}, fmt.Errorf("create meeting: commit: %w", err)
	}
	committed = true
	return repo.CreateResult{Meeting: in.Meeting, Replayed: false, NumberCiphertext: in.NumberCiphertext, LinkCiphertext: in.LinkCiphertext}, nil
}

func (s *MySQLStore) insertMeeting(ctx context.Context, tx *sql.Tx, m repo.Meeting) error {
	var sched sql.NullTime
	if !m.ScheduledStartAt.IsZero() {
		sched = sql.NullTime{Time: m.ScheduledStartAt.UTC(), Valid: true}
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO meeting (meeting_id, space_id, type, status, creator_uid, host_uid,
			scheduled_start_at, password_enabled, locked, max_participants, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		m.MeetingID, m.SpaceID, string(m.Type), string(m.Status), m.CreatorUID, m.HostUID,
		sched, m.PasswordEnabled, m.MaxParticipants, m.Version)
	if err != nil {
		return fmt.Errorf("create meeting: insert meeting: %w", err)
	}
	return nil
}

func (s *MySQLStore) insertCredential(ctx context.Context, tx *sql.Tx, in repo.CreateInput) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO meeting_credential (meeting_id, number_lookup_hash, number_display_ciphertext,
			link_token_lookup_hash, link_token_ciphertext, status)
		 VALUES (?, ?, ?, ?, ?, 'active')`,
		in.Meeting.MeetingID, s.lookupHash(in.Number), in.NumberCiphertext,
		s.lookupHash(in.LinkToken), in.LinkCiphertext)
	if err != nil {
		return fmt.Errorf("create meeting: insert credential: %w", err)
	}
	return nil
}

func (s *MySQLStore) insertVerifier(ctx context.Context, tx *sql.Tx, meetingID, createdBy string, v repo.VerifierInput) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO meeting_password_verifier (meeting_id, algorithm, params_json, salt_id, pepper_ref, verifier, status, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
		meetingID, v.Algorithm, v.ParamsJSON, v.SaltID, v.PepperRef, []byte(v.Verifier), createdBy)
	if err != nil {
		return fmt.Errorf("create meeting: insert verifier: %w", err)
	}
	return nil
}
