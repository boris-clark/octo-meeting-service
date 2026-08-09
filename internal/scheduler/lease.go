// Package scheduler holds the deterministic job-lease state machine shared by
// the reminder and outbox workers: claim eligibility, success/failure
// transitions, bounded exponential backoff, dead-lettering, and the dedupe-key
// builders (backend appendix §11). It is pure so retry/dead-letter behaviour is
// unit-tested with a deterministic clock; the DB claim (FOR UPDATE SKIP LOCKED)
// and Redis lease live in the storage layer.
package scheduler

import (
	"fmt"
	"time"
)

// Status is a job's lifecycle state (reminder or outbox).
type Status string

// Job lifecycle states.
const (
	StatusPending   Status = "pending"
	StatusLeased    Status = "leased"
	StatusSent      Status = "sent"
	StatusFailed    Status = "failed"
	StatusDead      Status = "dead"
	StatusCancelled Status = "cancelled"
)

// Job is the schedulable unit (subset of the persisted row needed for the state
// machine).
type Job struct {
	Status        Status
	AttemptCount  int
	LeaseOwner    string
	LeaseUntil    time.Time
	NextAttemptAt time.Time
}

// Policy bounds retries and backoff.
type Policy struct {
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	LeaseTTL    time.Duration
}

// DefaultPolicy returns conservative worker defaults.
func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 5, BaseBackoff: 2 * time.Second, MaxBackoff: 5 * time.Minute, LeaseTTL: 30 * time.Second}
}

// Claimable reports whether a job may be leased now: it is pending or failed,
// its next-attempt time has arrived, and no live lease is held.
func Claimable(j Job, now time.Time) bool {
	switch j.Status {
	case StatusPending, StatusFailed:
	default:
		return false
	}
	if !j.NextAttemptAt.IsZero() && now.Before(j.NextAttemptAt) {
		return false
	}
	if !j.LeaseUntil.IsZero() && now.Before(j.LeaseUntil) {
		return false
	}
	return true
}

// Claim leases a claimable job to owner until now+LeaseTTL. It returns the job
// unchanged if it is not claimable.
func (p Policy) Claim(j Job, owner string, now time.Time) (Job, bool) {
	if !Claimable(j, now) {
		return j, false
	}
	j.Status = StatusLeased
	j.LeaseOwner = owner
	j.LeaseUntil = now.Add(p.leaseTTL())
	return j, true
}

// OnSuccess marks a leased job sent.
func OnSuccess(j Job) Job {
	j.Status = StatusSent
	j.LeaseOwner = ""
	j.LeaseUntil = time.Time{}
	return j
}

// OnFailure records a failed attempt: it dead-letters once MaxAttempts is
// reached, otherwise schedules a backed-off retry.
func (p Policy) OnFailure(j Job, now time.Time) Job {
	j.AttemptCount++
	j.LeaseOwner = ""
	j.LeaseUntil = time.Time{}
	if j.AttemptCount >= p.maxAttempts() {
		j.Status = StatusDead
		j.NextAttemptAt = time.Time{}
		return j
	}
	j.Status = StatusFailed
	j.NextAttemptAt = now.Add(p.Backoff(j.AttemptCount))
	return j
}

// Backoff returns the delay before retry attempt n (1-based), exponential from
// BaseBackoff and capped at MaxBackoff.
func (p Policy) Backoff(attempt int) time.Duration {
	base := p.baseBackoff()
	d := base
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= p.maxBackoff() {
			return p.maxBackoff()
		}
	}
	if d > p.maxBackoff() {
		return p.maxBackoff()
	}
	return d
}

func (p Policy) maxAttempts() int {
	if p.MaxAttempts <= 0 {
		return 5
	}
	return p.MaxAttempts
}
func (p Policy) baseBackoff() time.Duration {
	if p.BaseBackoff <= 0 {
		return 2 * time.Second
	}
	return p.BaseBackoff
}
func (p Policy) maxBackoff() time.Duration {
	if p.MaxBackoff <= 0 {
		return 5 * time.Minute
	}
	return p.MaxBackoff
}
func (p Policy) leaseTTL() time.Duration {
	if p.LeaseTTL <= 0 {
		return 30 * time.Second
	}
	return p.LeaseTTL
}

// ReminderDedupeKey builds the one-time reminder dedupe key, versioned by the
// scheduled-start version so a reschedule produces a fresh reminder.
func ReminderDedupeKey(meetingID, uid string, startVersion int64) string {
	return fmt.Sprintf("meeting:%s:reminder:%s:start:%d", meetingID, uid, startVersion)
}

// InviteDedupeKey builds the invite-notification dedupe key, versioned by the
// invite version.
func InviteDedupeKey(meetingID, uid string, inviteVersion int64) string {
	return fmt.Sprintf("meeting:%s:invite:%s:v%d", meetingID, uid, inviteVersion)
}
