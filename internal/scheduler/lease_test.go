package scheduler

import (
	"testing"
	"time"
)

func TestClaimable(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if !Claimable(Job{Status: StatusPending}, now) {
		t.Error("fresh pending job should be claimable")
	}
	if Claimable(Job{Status: StatusSent}, now) {
		t.Error("sent job must not be claimable")
	}
	if Claimable(Job{Status: StatusDead}, now) {
		t.Error("dead job must not be claimable")
	}
	// Not yet due.
	if Claimable(Job{Status: StatusFailed, NextAttemptAt: now.Add(time.Minute)}, now) {
		t.Error("job before next_attempt_at must not be claimable")
	}
	// Live lease held.
	if Claimable(Job{Status: StatusPending, LeaseUntil: now.Add(time.Minute)}, now) {
		t.Error("leased job must not be re-claimable before lease expiry")
	}
	// Expired lease is reclaimable.
	if !Claimable(Job{Status: StatusFailed, LeaseUntil: now.Add(-time.Second)}, now) {
		t.Error("expired lease should be reclaimable")
	}
}

func TestClaimAndSuccess(t *testing.T) {
	p := DefaultPolicy()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	j, ok := p.Claim(Job{Status: StatusPending}, "worker-1", now)
	if !ok || j.Status != StatusLeased || j.LeaseOwner != "worker-1" {
		t.Fatalf("claim failed: %+v ok=%v", j, ok)
	}
	if !j.LeaseUntil.Equal(now.Add(p.LeaseTTL)) {
		t.Fatalf("lease until = %v", j.LeaseUntil)
	}
	// A second worker cannot claim the leased job.
	if _, ok := p.Claim(j, "worker-2", now); ok {
		t.Fatal("second claim on live lease must fail")
	}
	done := OnSuccess(j)
	if done.Status != StatusSent || done.LeaseOwner != "" {
		t.Fatalf("success state wrong: %+v", done)
	}
}

func TestFailureRetryThenDeadLetter(t *testing.T) {
	p := Policy{MaxAttempts: 3, BaseBackoff: time.Second, MaxBackoff: time.Minute, LeaseTTL: 10 * time.Second}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	j := Job{Status: StatusLeased}

	j = p.OnFailure(j, now)
	if j.Status != StatusFailed || j.AttemptCount != 1 || !j.NextAttemptAt.Equal(now.Add(time.Second)) {
		t.Fatalf("attempt 1: %+v", j)
	}
	j = p.OnFailure(j, now)
	if j.Status != StatusFailed || j.AttemptCount != 2 || !j.NextAttemptAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("attempt 2: %+v", j)
	}
	j = p.OnFailure(j, now)
	if j.Status != StatusDead || j.AttemptCount != 3 {
		t.Fatalf("attempt 3 should dead-letter: %+v", j)
	}
}

func TestBackoffCap(t *testing.T) {
	p := Policy{MaxAttempts: 20, BaseBackoff: time.Second, MaxBackoff: 10 * time.Second}
	if got := p.Backoff(1); got != time.Second {
		t.Errorf("attempt 1 backoff = %v, want 1s", got)
	}
	if got := p.Backoff(2); got != 2*time.Second {
		t.Errorf("attempt 2 backoff = %v, want 2s", got)
	}
	if got := p.Backoff(4); got != 8*time.Second {
		t.Errorf("attempt 4 backoff = %v, want 8s", got)
	}
	if got := p.Backoff(10); got != 10*time.Second {
		t.Errorf("attempt 10 backoff = %v, want capped 10s", got)
	}
}

func TestDedupeKeys(t *testing.T) {
	if got := ReminderDedupeKey("m1", "u1", 3); got != "meeting:m1:reminder:u1:start:3" {
		t.Errorf("reminder key = %q", got)
	}
	if got := InviteDedupeKey("m1", "u1", 2); got != "meeting:m1:invite:u1:v2" {
		t.Errorf("invite key = %q", got)
	}
	// A reschedule (new start version) yields a distinct reminder key.
	if ReminderDedupeKey("m1", "u1", 3) == ReminderDedupeKey("m1", "u1", 4) {
		t.Error("reschedule must change reminder dedupe key")
	}
}
