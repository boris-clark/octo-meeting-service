package repo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// ErrIdempotencyConflict is returned when an idempotency key is reused with a
// different payload.
var ErrIdempotencyConflict = errors.New("idempotency conflict")

// CooldownStore persists per-user+meeting password attempt state. The production
// implementation is Redis-atomic on the hot path; the in-memory version backs
// tests.
type CooldownStore interface {
	Get(ctx context.Context, meetingID, uid string) (password.State, error)
	Put(ctx context.Context, meetingID, uid string, s password.State) error
}

// MemCooldownStore is an in-memory CooldownStore.
type MemCooldownStore struct {
	mu sync.Mutex
	m  map[string]password.State
}

// NewMemCooldownStore builds an empty cooldown store.
func NewMemCooldownStore() *MemCooldownStore {
	return &MemCooldownStore{m: map[string]password.State{}}
}

// Get implements CooldownStore.
func (s *MemCooldownStore) Get(_ context.Context, meetingID, uid string) (password.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key(meetingID, uid)], nil
}

// Put implements CooldownStore.
func (s *MemCooldownStore) Put(_ context.Context, meetingID, uid string, st password.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key(meetingID, uid)] = st
	return nil
}

// PassTokenStore issues and validates single-use-on-success password pass
// tokens. A token is bound to a meeting+user and expires at a TTL. Single-use is
// enforced by a reserve/commit protocol: Reserve atomically re-validates and
// takes a single-flight reservation before LiveKit mint; Commit consumes on mint
// success; Release clears the reservation so a LiveKit failure can retry.
type PassTokenStore interface {
	Issue(ctx context.Context, meetingID, uid string, expiresAt time.Time) (string, error)
	Valid(ctx context.Context, token, meetingID, uid string, now time.Time) (bool, error)
	ValidForUser(ctx context.Context, meetingID, uid string, now time.Time) (bool, error)
	// Reserve atomically re-validates the token and takes a single-flight
	// reservation. ok=false => invalid/expired; reserved=false => another finalize
	// already holds the reservation.
	Reserve(ctx context.Context, token, meetingID, uid string, now time.Time) (ok bool, reserved bool, err error)
	// Commit deletes the token, its user marker, and the reservation (single-use).
	Commit(ctx context.Context, token, meetingID, uid string) error
	// Release clears only the reservation, leaving the token valid for retry.
	Release(ctx context.Context, token string) error
	// Consume removes a token given only the token (outside the reserve protocol).
	Consume(ctx context.Context, token string) error
}

type passEntry struct {
	meetingID string
	uid       string
	expiresAt time.Time
	reserved  bool
}

// MemPassTokenStore is an in-memory PassTokenStore. Its mutex makes the
// reserve/commit protocol trivially atomic.
type MemPassTokenStore struct {
	mu sync.Mutex
	m  map[string]passEntry
}

// NewMemPassTokenStore builds an empty pass-token store.
func NewMemPassTokenStore() *MemPassTokenStore { return &MemPassTokenStore{m: map[string]passEntry{}} }

// Issue implements PassTokenStore.
func (s *MemPassTokenStore) Issue(_ context.Context, meetingID, uid string, expiresAt time.Time) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("pass token: random: %w", err)
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = passEntry{meetingID: meetingID, uid: uid, expiresAt: expiresAt}
	return token, nil
}

// Valid implements PassTokenStore.
func (s *MemPassTokenStore) Valid(_ context.Context, token, meetingID, uid string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if !ok {
		return false, nil
	}
	return e.meetingID == meetingID && e.uid == uid && now.Before(e.expiresAt), nil
}

// ValidForUser implements PassTokenStore.
func (s *MemPassTokenStore) ValidForUser(_ context.Context, meetingID, uid string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.m {
		if e.meetingID == meetingID && e.uid == uid && now.Before(e.expiresAt) {
			return true, nil
		}
	}
	return false, nil
}

// Reserve implements PassTokenStore.
func (s *MemPassTokenStore) Reserve(_ context.Context, token, meetingID, uid string, now time.Time) (bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if !ok || e.meetingID != meetingID || e.uid != uid || !now.Before(e.expiresAt) {
		return false, false, nil
	}
	if e.reserved {
		return true, false, nil
	}
	e.reserved = true
	s.m[token] = e
	return true, true, nil
}

// Commit implements PassTokenStore.
func (s *MemPassTokenStore) Commit(_ context.Context, token, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
	return nil
}

// Release implements PassTokenStore.
func (s *MemPassTokenStore) Release(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[token]; ok {
		e.reserved = false
		s.m[token] = e
	}
	return nil
}

// Consume implements PassTokenStore.
func (s *MemPassTokenStore) Consume(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
	return nil
}

// PasswordVerifier checks a raw 6-digit password against the stored
// non-reversible verifier for a meeting. The production implementation runs the
// Argon2id/bcrypt comparison (OD-08); the in-memory version backs tests. A raw
// password is never stored or logged by callers.
type PasswordVerifier interface {
	Verify(ctx context.Context, meetingID, raw string) (bool, error)
}

// MemPasswordVerifier is an in-memory PasswordVerifier keyed by meeting id. It
// stores the expected password only to exercise the flow in tests; production
// uses a hashed verifier.
type MemPasswordVerifier struct {
	mu       sync.Mutex
	expected map[string]string
}

// NewMemPasswordVerifier builds an empty verifier.
func NewMemPasswordVerifier() *MemPasswordVerifier {
	return &MemPasswordVerifier{expected: map[string]string{}}
}

// Set registers the expected password for a meeting (test helper).
func (v *MemPasswordVerifier) Set(meetingID, raw string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expected[meetingID] = raw
}

// Verify implements PasswordVerifier.
func (v *MemPasswordVerifier) Verify(_ context.Context, meetingID, raw string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	exp, ok := v.expected[meetingID]
	if !ok {
		return false, nil
	}
	return password.EqualConstantTime([]byte(exp), []byte(raw)), nil
}
