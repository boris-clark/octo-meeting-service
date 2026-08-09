package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/scheduler"
)

// memJobStore is an in-memory JobStore modelling claim/settle for unit tests.
type memJobStore struct {
	jobs map[string]*jobRow
}

type jobRow struct {
	job     Job
	status  scheduler.Status
	dueAt   time.Time
	nextAt  time.Time
	attempt int
}

func newMemJobStore() *memJobStore { return &memJobStore{jobs: map[string]*jobRow{}} }

func (s *memJobStore) add(id, uid, template string, dueAt time.Time) {
	s.jobs[id] = &jobRow{
		job:    Job{ID: id, RecipientUID: uid, Template: template},
		status: scheduler.StatusPending,
		dueAt:  dueAt,
	}
}

func (s *memJobStore) ClaimDue(_ context.Context, now time.Time, _ string, limit int) ([]Job, error) {
	var out []Job
	for _, r := range s.jobs {
		if len(out) >= limit {
			break
		}
		ready := r.status == scheduler.StatusPending || r.status == scheduler.StatusFailed
		if !ready {
			continue
		}
		if !r.dueAt.IsZero() && now.Before(r.dueAt) {
			continue
		}
		if !r.nextAt.IsZero() && now.Before(r.nextAt) {
			continue
		}
		r.status = scheduler.StatusLeased
		j := r.job
		j.AttemptCount = r.attempt
		out = append(out, j)
	}
	return out, nil
}

func (s *memJobStore) MarkSent(_ context.Context, id string) error {
	s.jobs[id].status = scheduler.StatusSent
	return nil
}
func (s *memJobStore) Reschedule(_ context.Context, id string, nextAt time.Time, attempt int, _ string) error {
	r := s.jobs[id]
	r.status = scheduler.StatusFailed
	r.nextAt = nextAt
	r.attempt = attempt
	return nil
}
func (s *memJobStore) MarkDead(_ context.Context, id, _ string) error {
	s.jobs[id].status = scheduler.StatusDead
	return nil
}

type fakeNotifier struct {
	err  error
	sent []string
}

func (f *fakeNotifier) Notify(_ context.Context, uid, _ string, _ map[string]any) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, uid)
	return nil
}

func TestDispatcherDeliversAndMarksSent(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	store := newMemJobStore()
	store.add("j1", "alice", "meeting_reminder", now.Add(-time.Minute)) // due
	store.add("j2", "bob", "meeting_invite", now.Add(time.Hour))        // not due
	notifier := &fakeNotifier{}
	d := NewDispatcher(store, notifier, scheduler.DefaultPolicy(), "w1", 10, nil)

	n, err := d.Tick(context.Background(), now)
	if err != nil || n != 1 {
		t.Fatalf("Tick: n=%d err=%v, want 1", n, err)
	}
	if store.jobs["j1"].status != scheduler.StatusSent {
		t.Fatalf("due job not sent: %v", store.jobs["j1"].status)
	}
	if store.jobs["j2"].status != scheduler.StatusPending {
		t.Fatalf("not-due job claimed: %v", store.jobs["j2"].status)
	}
	// A sent job is never re-claimed (idempotent delivery).
	if n, _ := d.Tick(context.Background(), now); n != 0 {
		t.Fatalf("re-tick claimed %d jobs, want 0 (sent not reclaimed)", n)
	}
}

func TestDispatcherRetriesThenDeadLetters(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	store := newMemJobStore()
	store.add("j1", "alice", "meeting_reminder", now.Add(-time.Minute))
	notifier := &fakeNotifier{err: errors.New("seam down")}
	pol := scheduler.Policy{MaxAttempts: 2, BaseBackoff: time.Second, MaxBackoff: time.Minute, LeaseTTL: time.Second}
	d := NewDispatcher(store, notifier, pol, "w1", 10, nil)

	// First failure -> rescheduled (failed), not due until backoff.
	if _, err := d.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if store.jobs["j1"].status != scheduler.StatusFailed {
		t.Fatalf("after failure: %v, want failed", store.jobs["j1"].status)
	}
	// Not reclaimed before its next-attempt time.
	if n, _ := d.Tick(context.Background(), now); n != 0 {
		t.Fatalf("reclaimed before backoff elapsed: %d", n)
	}
	// After backoff, the second failure hits MaxAttempts -> dead-lettered.
	if _, err := d.Tick(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if store.jobs["j1"].status != scheduler.StatusDead {
		t.Fatalf("after max attempts: %v, want dead", store.jobs["j1"].status)
	}
}
