// Package meeting holds the deterministic core of meeting lifecycle: the status
// state machine, the server-clock time-window predicates (early-join window,
// reconnect grace, empty-room timeout, reminder offset), the quick-create
// idempotency bucket, and host-transfer target selection. Everything here is
// pure so the frozen boundaries (599s/601s, 14.9s/15.1s, etc.) are asserted with
// a deterministic clock (architecture §4/§5 / backend appendix §8).
package meeting

import (
	"fmt"
	"sort"
	"time"
)

// Status is the persisted meeting status. No intermediate states exist.
type Status string

// The only allowed persisted statuses.
const (
	StatusScheduled Status = "scheduled"
	StatusLive      Status = "live"
	StatusEnded     Status = "ended"
	StatusCancelled Status = "cancelled"
)

// Type is the meeting creation type.
type Type string

// Meeting types.
const (
	TypeQuick     Type = "quick"
	TypeScheduled Type = "scheduled"
)

// Frozen default constants (see architecture §13). Callers may override with
// configured values; the defaults match the approved contract.
const (
	DefaultEarlyJoinWindow = 600 * time.Second // MEETING_EARLY_JOIN_WINDOW_SECONDS
	DefaultReconnectGrace  = 15 * time.Second  // MEETING_RECONNECT_GRACE_SECONDS
	DefaultEmptyTimeout    = 5 * time.Minute   // MEETING_EMPTY_TIMEOUT_SECONDS
	DefaultReminderOffset  = 900 * time.Second // MEETING_REMINDER_OFFSET_SECONDS
	QuickCreateBucket      = 2 * time.Second   // FD-11 implicit idempotency window
)

// allowedTransitions is the meeting status state machine. Terminal states
// (ended, cancelled) have no outgoing edges.
var allowedTransitions = map[Status]map[Status]bool{
	StatusScheduled: {
		StatusLive:      true, // first successful finalize
		StatusCancelled: true, // creator/host cancels before live
		StatusEnded:     true, // scheduled no-show at start+duration
	},
	StatusLive: {
		StatusEnded: true, // host end / empty timeout / system
	},
}

// CanTransition reports whether from -> to is a legal status transition.
func CanTransition(from, to Status) bool {
	return allowedTransitions[from][to]
}

// IsTerminal reports whether a status is terminal.
func IsTerminal(s Status) bool {
	return s == StatusEnded || s == StatusCancelled
}

// EarliestJoinAt returns scheduledStart - window; a caller may join at or after
// this instant. window <= 0 falls back to the default.
func EarliestJoinAt(scheduledStart time.Time, window time.Duration) time.Time {
	if window <= 0 {
		window = DefaultEarlyJoinWindow
	}
	return scheduledStart.Add(-window)
}

// WithinEarlyJoinWindow reports whether now is within the early-join window for a
// scheduled meeting: now >= scheduledStart - window. Deterministic at the 600s
// boundary (599s in, 601s too early).
func WithinEarlyJoinWindow(now, scheduledStart time.Time, window time.Duration) bool {
	return !now.Before(EarliestJoinAt(scheduledStart, window))
}

// WithinReconnectGrace reports whether a same-endpoint reconnect is inside the
// 15s business grace measured from the authoritative segment.leave_at. A zero
// leaveAt (unknown disconnect time) or a different endpoint is never in grace.
// Deterministic at the boundary (14.9s in, 15.1s out).
func WithinReconnectGrace(now, leaveAt time.Time, grace time.Duration, sameEndpoint bool) bool {
	if !sameEndpoint || leaveAt.IsZero() {
		return false
	}
	if grace <= 0 {
		grace = DefaultReconnectGrace
	}
	return now.Sub(leaveAt) <= grace && !now.Before(leaveAt)
}

// EmptyTimeoutDueAt returns emptySince + timeout, the instant at which an empty
// room may be torn down (subject to a re-check of the authoritative active
// count under the meeting lock).
func EmptyTimeoutDueAt(emptySince time.Time, timeout time.Duration) time.Time {
	if timeout <= 0 {
		timeout = DefaultEmptyTimeout
	}
	return emptySince.Add(timeout)
}

// ReminderDueAt returns scheduledStart - offset, when the one-time reminder is
// due. If already past at scheduling time the caller decides to enqueue-now or
// skip per product copy; this function only computes the instant.
func ReminderDueAt(scheduledStart time.Time, offset time.Duration) time.Time {
	if offset <= 0 {
		offset = DefaultReminderOffset
	}
	return scheduledStart.Add(-offset)
}

// IsNoShowEligible reports whether a meeting qualifies for the scheduled no-show
// terminal transition: type=scheduled, still scheduled, and never started.
func IsNoShowEligible(t Type, status Status, hasActualStart bool) bool {
	return t == TypeScheduled && status == StatusScheduled && !hasActualStart
}

// QuickCreateImplicitKey returns the FD-11 implicit idempotency key derived from
// space_id + creator_uid + floor(server_now / 2s). Two quick-creates by the same
// creator in the same Space within a 2s window collapse to one key.
func QuickCreateImplicitKey(spaceID, creatorUID string, now time.Time) string {
	bucket := now.UnixNano() / int64(QuickCreateBucket)
	return fmt.Sprintf("%s:%s:%d", spaceID, creatorUID, bucket)
}

// ActiveSegment is a candidate for host transfer: an active (not superseded, not
// left, not removed) participant segment.
type ActiveSegment struct {
	UID    string
	JoinAt time.Time
}

// SelectHostTransferTarget picks the FD-06 successor host: the earliest joiner
// among the active segments, breaking exact join_at ties by ascending uid. It
// returns ok=false when there is no candidate. The input is not mutated.
func SelectHostTransferTarget(candidates []ActiveSegment) (string, bool) {
	if len(candidates) == 0 {
		return "", false
	}
	sorted := make([]ActiveSegment, len(candidates))
	copy(sorted, candidates)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].JoinAt.Equal(sorted[j].JoinAt) {
			return sorted[i].UID < sorted[j].UID
		}
		return sorted[i].JoinAt.Before(sorted[j].JoinAt)
	})
	return sorted[0].UID, true
}
