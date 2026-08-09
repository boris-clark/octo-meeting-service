// Package password implements the deterministic parts of the meeting password
// flow: 6-digit format validation, the per-user+meeting attempt/cooldown state
// machine (FD-28), and a constant-time comparison helper. Verifier hashing
// (Argon2id/bcrypt per OD-08) and the Redis-backed hot path live elsewhere; this
// package is pure so the boundaries are unit-testable with a deterministic clock.
package password

import (
	"crypto/subtle"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
)

// Format is the frozen password format: exactly six decimal digits.
const Format = "6_digit"

// DefaultMaxAttempts and DefaultCooldown are the frozen defaults
// (MEETING_COOLDOWN_ATTEMPTS / MEETING_COOLDOWN_SECONDS). The 5th consecutive
// wrong attempt enters a 5-minute cooldown.
const (
	DefaultMaxAttempts = 5
	DefaultCooldown    = 5 * time.Minute
)

// Policy holds the tunable attempt budget and cooldown duration.
type Policy struct {
	MaxAttempts int
	Cooldown    time.Duration
}

// DefaultPolicy returns the frozen defaults.
func DefaultPolicy() Policy {
	return Policy{MaxAttempts: DefaultMaxAttempts, Cooldown: DefaultCooldown}
}

// State is the per-user+meeting attempt state. The zero value is a fresh state.
type State struct {
	Attempts      int
	CooldownUntil time.Time
}

// Outcome is the result of processing one verify attempt.
type Outcome struct {
	// Code is "" on success, otherwise the stable error to return.
	Code merr.Code
	// Success is true only when the password matched and no cooldown was active.
	Success bool
	// AttemptsRemaining is meaningful when Code == MEETING_PASSWORD_INVALID.
	AttemptsRemaining int
	// CooldownUntil is set when Code == MEETING_PASSWORD_COOLDOWN.
	CooldownUntil time.Time
}

// CheckFormat validates the raw password. A format failure is rejected before
// any verifier lookup and MUST NOT count against the attempt budget, so callers
// invoke this before Verify. It returns nil when the format is valid.
func CheckFormat(raw string) *merr.Error {
	if len(raw) != 6 {
		return formatError()
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return formatError()
		}
	}
	return nil
}

func formatError() *merr.Error {
	return merr.New(merr.PasswordFormatInvalid, "The password must be 6 digits.").
		WithDetail("format", Format)
}

// Verify processes a single format-valid attempt against the current state using
// the injected clock. correct reports whether the verifier matched. It returns
// the next state and the outcome. An active cooldown short-circuits before any
// verifier check; an expired cooldown is atomically cleared first, and a success
// resets the state.
func (p Policy) Verify(s State, now time.Time, correct bool) (State, Outcome) {
	max := p.MaxAttempts
	if max <= 0 {
		max = DefaultMaxAttempts
	}

	// Active cooldown: reject without checking the verifier.
	if !s.CooldownUntil.IsZero() && now.Before(s.CooldownUntil) {
		return s, Outcome{Code: merr.PasswordCooldown, CooldownUntil: s.CooldownUntil}
	}
	// Expired cooldown (or none): start from a clean slate for this attempt.
	if !s.CooldownUntil.IsZero() {
		s = State{}
	}

	if correct {
		return State{}, Outcome{Success: true}
	}

	s.Attempts++
	if s.Attempts >= max {
		until := now.Add(p.cooldown())
		return State{Attempts: s.Attempts, CooldownUntil: until},
			Outcome{Code: merr.PasswordCooldown, CooldownUntil: until}
	}
	return s, Outcome{Code: merr.PasswordInvalid, AttemptsRemaining: max - s.Attempts}
}

func (p Policy) cooldown() time.Duration {
	if p.Cooldown <= 0 {
		return DefaultCooldown
	}
	return p.Cooldown
}

// EqualConstantTime compares two verifier byte slices in constant time to avoid
// leaking match progress through timing. It is used for fixed-length derived
// comparisons where a non-constant-time library primitive is not already used.
func EqualConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
