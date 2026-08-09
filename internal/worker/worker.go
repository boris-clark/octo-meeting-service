// Package worker runs bounded background jobs with graceful shutdown. The
// bootstrap ships the lifecycle and concurrency ownership only; no meeting jobs
// are implemented yet.
package worker

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
)

// Worker owns a bounded pool of goroutines and shuts them down cleanly when its
// context is cancelled.
type Worker struct {
	cfg    config.WorkerConfig
	logger *zap.Logger
	wg     sync.WaitGroup
}

// New constructs a Worker.
func New(cfg config.WorkerConfig, logger *zap.Logger) *Worker {
	return &Worker{cfg: cfg, logger: logger}
}

// Run starts the worker loops and blocks until ctx is cancelled, then waits for
// in-flight loops to drain. It never leaks goroutines past return.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("worker starting", zap.Int("concurrency", w.cfg.Concurrency))
	for i := 0; i < w.cfg.Concurrency; i++ {
		w.wg.Add(1)
		go w.loop(ctx, i)
	}
	<-ctx.Done()
	w.logger.Info("worker draining")
	w.wg.Wait()
	w.logger.Info("worker stopped")
}

// loop is a single bounded worker. In the bootstrap it only observes shutdown;
// job dispatch is added with the domain layer.
func (w *Worker) loop(ctx context.Context, id int) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.cfg.PollBackoff)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Placeholder: no jobs are dispatched in the bootstrap.
		}
	}
}
