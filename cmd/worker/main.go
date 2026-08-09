// Command worker runs the background job processor for the Octo Meeting
// service. It drives the outbox/reminder dispatch loop against MySQL with
// retry/dead-letter and graceful shutdown.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
	"github.com/Jerry-Xin/octo-meeting-service/internal/scheduler"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams/httpclient"
	"github.com/Jerry-Xin/octo-meeting-service/internal/storage"
	"github.com/Jerry-Xin/octo-meeting-service/internal/worker"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger, err := observability.NewLogger(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	db, err := storage.OpenMySQL(cfg.MySQL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	redisClient := storage.OpenRedis(cfg.Redis)
	defer func() { _ = redisClient.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wire the outbox/reminder dispatcher: claim due jobs from MySQL and deliver
	// them through the fail-closed notification seam with retry/dead-letter.
	notifier := httpclient.NewNotificationClient(httpclient.Options{
		BaseURL:      cfg.Seams.Notification.BaseURL,
		ServiceToken: cfg.Internal.ServiceToken,
		HTTPClient:   &http.Client{Timeout: cfg.Seams.Notification.Timeout},
	})
	dispatcher := worker.NewDispatcher(
		storage.NewMySQLJobStore(db), notifier, scheduler.DefaultPolicy(),
		leaseOwner(), cfg.Worker.Concurrency*8, logger,
	)

	w := worker.New(cfg.Worker, logger).WithDispatcher(dispatcher)
	w.Run(ctx) // blocks until signal, then drains
	logger.Info("worker exited cleanly")
	return nil
}

// leaseOwner identifies this worker instance for job leases (SKIP LOCKED handles
// concurrency regardless; the owner is for observability/lease reclaim).
func leaseOwner() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "meeting-worker"
}
