package worker

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/scheduler"
)

// Notifier delivers a redacted notification intent. It matches seams.Notification
// so the notification seam client plugs in directly. The payload must already be
// free of secrets (no raw password, link/pass token, or LiveKit token).
type Notifier interface {
	Notify(ctx context.Context, userID, template string, payload map[string]any) error
}

// Job is one claimable delivery (reminder or outbox row). AttemptCount is the
// number of failures so far.
type Job struct {
	ID           string
	RecipientUID string
	Template     string
	Payload      map[string]any
	AttemptCount int
}

// JobStore is the durable job queue. ClaimDue leases due, ready jobs (production:
// FOR UPDATE SKIP LOCKED); the settle methods persist the state-machine outcome.
// Delivery is idempotent because a sent job is never re-claimed and rows are
// deduped by dedupe_key at enqueue time.
type JobStore interface {
	ClaimDue(ctx context.Context, now time.Time, owner string, limit int) ([]Job, error)
	MarkSent(ctx context.Context, jobID string) error
	Reschedule(ctx context.Context, jobID string, nextAttemptAt time.Time, attemptCount int, lastErr string) error
	MarkDead(ctx context.Context, jobID string, lastErr string) error
}

// Dispatcher claims due jobs and delivers them through the notifier, applying the
// scheduler retry/dead-letter state machine on failure.
type Dispatcher struct {
	store    JobStore
	notifier Notifier
	policy   scheduler.Policy
	owner    string
	batch    int
	logger   *zap.Logger
}

// NewDispatcher builds a Dispatcher.
func NewDispatcher(store JobStore, notifier Notifier, policy scheduler.Policy, owner string, batch int, logger *zap.Logger) *Dispatcher {
	if batch <= 0 {
		batch = 32
	}
	return &Dispatcher{store: store, notifier: notifier, policy: policy, owner: owner, batch: batch, logger: logger}
}

// Tick claims one batch of due jobs and delivers them. It returns the number of
// jobs processed. A per-job failure is isolated: it is rescheduled or
// dead-lettered, and processing continues.
func (d *Dispatcher) Tick(ctx context.Context, now time.Time) (int, error) {
	jobs, err := d.store.ClaimDue(ctx, now, d.owner, d.batch)
	if err != nil {
		return 0, err
	}
	for _, j := range jobs {
		if derr := d.notifier.Notify(ctx, j.RecipientUID, j.Template, j.Payload); derr != nil {
			nj := d.policy.OnFailure(scheduler.Job{Status: scheduler.StatusLeased, AttemptCount: j.AttemptCount}, now)
			if nj.Status == scheduler.StatusDead {
				if err := d.store.MarkDead(ctx, j.ID, derr.Error()); err != nil {
					d.logf("mark dead", j.ID, err)
				}
				continue
			}
			if err := d.store.Reschedule(ctx, j.ID, nj.NextAttemptAt, nj.AttemptCount, derr.Error()); err != nil {
				d.logf("reschedule", j.ID, err)
			}
			continue
		}
		if err := d.store.MarkSent(ctx, j.ID); err != nil {
			d.logf("mark sent", j.ID, err)
		}
	}
	return len(jobs), nil
}

func (d *Dispatcher) logf(op, jobID string, err error) {
	if d.logger != nil {
		d.logger.Warn("dispatch: "+op+" failed", zap.String("job_id", jobID), zap.Error(err))
	}
}
