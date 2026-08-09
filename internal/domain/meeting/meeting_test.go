package meeting

import (
	"testing"
	"time"
)

func TestStatusTransitions(t *testing.T) {
	valid := [][2]Status{
		{StatusScheduled, StatusLive},
		{StatusScheduled, StatusCancelled},
		{StatusScheduled, StatusEnded},
		{StatusLive, StatusEnded},
	}
	for _, tr := range valid {
		if !CanTransition(tr[0], tr[1]) {
			t.Errorf("expected %s -> %s allowed", tr[0], tr[1])
		}
	}
	invalid := [][2]Status{
		{StatusLive, StatusScheduled},
		{StatusLive, StatusCancelled},
		{StatusEnded, StatusLive},
		{StatusCancelled, StatusLive},
		{StatusEnded, StatusEnded},
	}
	for _, tr := range invalid {
		if CanTransition(tr[0], tr[1]) {
			t.Errorf("expected %s -> %s forbidden", tr[0], tr[1])
		}
	}
	if !IsTerminal(StatusEnded) || !IsTerminal(StatusCancelled) {
		t.Fatal("ended/cancelled must be terminal")
	}
	if IsTerminal(StatusScheduled) || IsTerminal(StatusLive) {
		t.Fatal("scheduled/live must not be terminal")
	}
}

func TestEarlyJoinWindowBoundary(t *testing.T) {
	start := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	w := DefaultEarlyJoinWindow

	// 601s before start: too early.
	if WithinEarlyJoinWindow(start.Add(-601*time.Second), start, w) {
		t.Error("601s before start should be too early")
	}
	// 599s before start: within window.
	if !WithinEarlyJoinWindow(start.Add(-599*time.Second), start, w) {
		t.Error("599s before start should be within window")
	}
	// Exactly 600s: within (>=).
	if !WithinEarlyJoinWindow(start.Add(-600*time.Second), start, w) {
		t.Error("exactly 600s before start should be within window")
	}
	if got := EarliestJoinAt(start, w); !got.Equal(start.Add(-600 * time.Second)) {
		t.Errorf("EarliestJoinAt = %v, want start-600s", got)
	}
}

func TestReconnectGraceBoundary(t *testing.T) {
	leaveAt := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	g := DefaultReconnectGrace

	// 14.9s same endpoint: in grace.
	if !WithinReconnectGrace(leaveAt.Add(14900*time.Millisecond), leaveAt, g, true) {
		t.Error("14.9s same endpoint should be in grace")
	}
	// 15.1s: out of grace.
	if WithinReconnectGrace(leaveAt.Add(15100*time.Millisecond), leaveAt, g, true) {
		t.Error("15.1s should be out of grace")
	}
	// Exactly 15s: in grace (<=).
	if !WithinReconnectGrace(leaveAt.Add(15*time.Second), leaveAt, g, true) {
		t.Error("exactly 15s should be in grace")
	}
	// Different endpoint: never in grace.
	if WithinReconnectGrace(leaveAt.Add(1*time.Second), leaveAt, g, false) {
		t.Error("different endpoint must not be in grace")
	}
	// Unknown leave time: never in grace.
	if WithinReconnectGrace(leaveAt.Add(1*time.Second), time.Time{}, g, true) {
		t.Error("zero leaveAt must not be in grace")
	}
}

func TestEmptyTimeoutAndReminder(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if got := EmptyTimeoutDueAt(base, DefaultEmptyTimeout); !got.Equal(base.Add(5 * time.Minute)) {
		t.Errorf("EmptyTimeoutDueAt = %v, want +5m", got)
	}
	if got := ReminderDueAt(base, DefaultReminderOffset); !got.Equal(base.Add(-15 * time.Minute)) {
		t.Errorf("ReminderDueAt = %v, want -15m", got)
	}
}

func TestNoShowEligibility(t *testing.T) {
	if !IsNoShowEligible(TypeScheduled, StatusScheduled, false) {
		t.Error("scheduled+scheduled+never-started should be no-show eligible")
	}
	if IsNoShowEligible(TypeQuick, StatusScheduled, false) {
		t.Error("quick meetings are never no-show candidates")
	}
	if IsNoShowEligible(TypeScheduled, StatusScheduled, true) {
		t.Error("a started meeting is not a no-show")
	}
	if IsNoShowEligible(TypeScheduled, StatusLive, false) {
		t.Error("a live meeting is not a no-show")
	}
}

func TestQuickCreateImplicitKey(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	k0 := QuickCreateImplicitKey("space1", "userA", base)
	k1 := QuickCreateImplicitKey("space1", "userA", base.Add(1900*time.Millisecond)) // same 2s bucket
	if k0 != k1 {
		t.Errorf("same 2s window must share a key: %q vs %q", k0, k1)
	}
	k2 := QuickCreateImplicitKey("space1", "userA", base.Add(2100*time.Millisecond)) // next bucket
	if k0 == k2 {
		t.Error("different 2s window must produce a different key")
	}
	if QuickCreateImplicitKey("space1", "userA", base) == QuickCreateImplicitKey("space2", "userA", base) {
		t.Error("different space must produce a different key")
	}
	if QuickCreateImplicitKey("space1", "userA", base) == QuickCreateImplicitKey("space1", "userB", base) {
		t.Error("different creator must produce a different key")
	}
}

func TestSelectHostTransferTarget(t *testing.T) {
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

	if _, ok := SelectHostTransferTarget(nil); ok {
		t.Error("no candidates should return ok=false")
	}

	// Earliest joiner wins.
	got, ok := SelectHostTransferTarget([]ActiveSegment{
		{UID: "u3", JoinAt: base.Add(3 * time.Second)},
		{UID: "u1", JoinAt: base.Add(1 * time.Second)},
		{UID: "u2", JoinAt: base.Add(2 * time.Second)},
	})
	if !ok || got != "u1" {
		t.Fatalf("earliest joiner: got %q ok=%v, want u1", got, ok)
	}

	// Exact join_at tie broken by ascending uid.
	got, ok = SelectHostTransferTarget([]ActiveSegment{
		{UID: "zeb", JoinAt: base},
		{UID: "amy", JoinAt: base},
		{UID: "bob", JoinAt: base},
	})
	if !ok || got != "amy" {
		t.Fatalf("tie-break: got %q, want amy", got)
	}
}
