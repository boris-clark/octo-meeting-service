package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// MySQLPasswordVerifier is the read side of the durable password verifier: it
// loads a meeting's active, non-reversible verifier from meeting_password_verifier
// and checks the candidate with the shared, constant-time Argon2id comparison.
// The pepper comes from secret config and is never stored.
type MySQLPasswordVerifier struct {
	db     *sql.DB
	pepper string
}

// NewMySQLPasswordVerifier builds the verifier.
func NewMySQLPasswordVerifier(db *sql.DB, pepper string) *MySQLPasswordVerifier {
	return &MySQLPasswordVerifier{db: db, pepper: pepper}
}

// Verify implements repo.PasswordVerifier. A meeting with no active verifier
// returns false (never an error), so a caller cannot distinguish "no password"
// from "wrong password" via the error channel.
func (v *MySQLPasswordVerifier) Verify(ctx context.Context, meetingID, raw string) (bool, error) {
	const q = `SELECT algorithm, verifier FROM meeting_password_verifier
		WHERE meeting_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
	var (
		algorithm string
		encoded   []byte
	)
	err := v.db.QueryRowContext(ctx, q, meetingID).Scan(&algorithm, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("password verifier load: %w", err)
	}
	if algorithm != password.Algorithm {
		return false, fmt.Errorf("password verifier: unsupported algorithm %q", algorithm)
	}
	return password.VerifyArgon2(string(encoded), v.pepper, raw)
}

var _ repo.PasswordVerifier = (*MySQLPasswordVerifier)(nil)
