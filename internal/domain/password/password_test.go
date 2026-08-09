package password

import (
	"testing"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
)

func TestCheckFormat(t *testing.T) {
	valid := []string{"000000", "123456", "999999"}
	for _, v := range valid {
		if err := CheckFormat(v); err != nil {
			t.Errorf("CheckFormat(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{"", "12345", "1234567", "12345a", "abcdef", " 12345", "12 456"}
	for _, v := range invalid {
		err := CheckFormat(v)
		if err == nil {
			t.Errorf("CheckFormat(%q) = nil, want format error", v)
			continue
		}
		if err.Code != merr.PasswordFormatInvalid {
			t.Errorf("CheckFormat(%q) code = %v", v, err.Code)
		}
		if err.Details["format"] != Format {
			t.Errorf("CheckFormat(%q) missing format detail", v)
		}
	}
}

func TestAttemptsThenCooldown(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := State{}

	// Wrong attempts 1..4 are retryable with a decreasing remaining count.
	for i := 1; i <= 4; i++ {
		var out Outcome
		s, out = p.Verify(s, now, false)
		if out.Code != merr.PasswordInvalid {
			t.Fatalf("attempt %d: code = %v, want PasswordInvalid", i, out.Code)
		}
		if want := 5 - i; out.AttemptsRemaining != want {
			t.Fatalf("attempt %d: remaining = %d, want %d", i, out.AttemptsRemaining, want)
		}
	}

	// The 5th wrong attempt enters cooldown.
	var out Outcome
	s, out = p.Verify(s, now, false)
	if out.Code != merr.PasswordCooldown {
		t.Fatalf("5th attempt: code = %v, want PasswordCooldown", out.Code)
	}
	if !out.CooldownUntil.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("cooldown until = %v, want now+5m", out.CooldownUntil)
	}

	// A request during cooldown is rejected without a verifier check, even if
	// the password would be correct.
	_, out = p.Verify(s, now.Add(1*time.Minute), true)
	if out.Code != merr.PasswordCooldown {
		t.Fatalf("during cooldown: code = %v, want PasswordCooldown", out.Code)
	}
	if out.Success {
		t.Fatal("verifier was checked during cooldown")
	}
}

func TestCooldownExpiryResetsThenAcceptsCorrect(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := State{Attempts: 5, CooldownUntil: now.Add(5 * time.Minute)}

	// Just before expiry: still cooling down.
	if _, out := p.Verify(s, now.Add(5*time.Minute-time.Millisecond), true); out.Code != merr.PasswordCooldown {
		t.Fatalf("pre-expiry: code = %v, want PasswordCooldown", out.Code)
	}

	// At/after expiry with a correct password: state resets and succeeds.
	ns, out := p.Verify(s, now.Add(5*time.Minute), true)
	if !out.Success {
		t.Fatalf("post-expiry correct: expected success, got %v", out.Code)
	}
	if ns.Attempts != 0 || !ns.CooldownUntil.IsZero() {
		t.Fatalf("post-expiry state not reset: %+v", ns)
	}
}

func TestCooldownExpiryThenWrongCountsFromZero(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	s := State{Attempts: 5, CooldownUntil: now.Add(5 * time.Minute)}

	ns, out := p.Verify(s, now.Add(5*time.Minute), false)
	if out.Code != merr.PasswordInvalid || out.AttemptsRemaining != 4 {
		t.Fatalf("post-expiry wrong: code=%v remaining=%d, want PasswordInvalid/4", out.Code, out.AttemptsRemaining)
	}
	if ns.Attempts != 1 {
		t.Fatalf("post-expiry wrong: attempts = %d, want 1", ns.Attempts)
	}
}

func TestCorrectResetsState(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	ns, out := p.Verify(State{Attempts: 3}, now, true)
	if !out.Success {
		t.Fatalf("expected success, got %v", out.Code)
	}
	if ns.Attempts != 0 || !ns.CooldownUntil.IsZero() {
		t.Fatalf("state not reset on success: %+v", ns)
	}
}

func TestEqualConstantTime(t *testing.T) {
	if !EqualConstantTime([]byte("verifier-abc"), []byte("verifier-abc")) {
		t.Fatal("equal slices reported unequal")
	}
	if EqualConstantTime([]byte("verifier-abc"), []byte("verifier-xyz")) {
		t.Fatal("unequal slices reported equal")
	}
	if EqualConstantTime([]byte("short"), []byte("longer-value")) {
		t.Fatal("different-length slices reported equal")
	}
}
