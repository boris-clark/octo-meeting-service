// Command api is the HTTP entrypoint for the Octo Meeting service. It boots the
// operational surface (health, readiness, metrics) and an empty versioned API
// group; meeting domain routes are added later.
package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/health"
	"github.com/Jerry-Xin/octo-meeting-service/internal/httpserver"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
	"github.com/Jerry-Xin/octo-meeting-service/internal/storage"
)

// Build metadata, injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(); err != nil {
		// Logger may not exist yet; fail loudly on stderr.
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

	metrics := observability.NewMetrics()
	metrics.SetBuildInfo(version, commit)

	db, err := storage.OpenMySQL(cfg.MySQL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	redisClient := storage.OpenRedis(cfg.Redis)
	defer func() { _ = redisClient.Close() }()

	// Verify dependencies once at startup; readiness re-checks continuously.
	if err := storage.PingMySQL(context.Background(), db, 5*time.Second); err != nil {
		logger.Warn("mysql not reachable at startup; readiness will report not_ready", zap.Error(err))
	}

	readiness := health.NewRegistry(2 * time.Second)
	readiness.Register(storage.MySQLChecker{DB: db})
	readiness.Register(storage.RedisChecker{Client: redisClient})

	engine := httpserver.NewEngine(httpserver.Deps{
		Config:  cfg,
		Logger:  logger,
		Metrics: metrics,
		Health:  readiness,
	})

	apiSrv := httpserver.NewHTTPServer(cfg.HTTP, engine)
	metricsSrv := &http.Server{Addr: cfg.HTTP.MetricsAddr, Handler: metrics.Handler()}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("api listening", zap.String("addr", cfg.HTTP.Addr), zap.String("base_path", cfg.HTTP.BasePath))
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("metrics listening", zap.String("addr", cfg.HTTP.MetricsAddr))
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	if err := httpserver.Shutdown(apiSrv, cfg.Shutdown.GracePeriod); err != nil {
		logger.Error("api shutdown", zap.Error(err))
	}
	if err := httpserver.Shutdown(metricsSrv, cfg.Shutdown.GracePeriod); err != nil {
		logger.Error("metrics shutdown", zap.Error(err))
	}
	return nil
}
