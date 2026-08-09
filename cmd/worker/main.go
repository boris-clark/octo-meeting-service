// Command worker runs the background job processor for the Octo Meeting
// service. The bootstrap wires lifecycle, dependencies, and graceful shutdown;
// no meeting jobs are implemented yet.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
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

	w := worker.New(cfg.Worker, logger)
	w.Run(ctx) // blocks until signal, then drains
	logger.Info("worker exited cleanly")
	return nil
}
