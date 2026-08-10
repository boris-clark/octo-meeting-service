// Command api is the HTTP entrypoint for the Octo Meeting service. It boots the
// operational surface (health, readiness, metrics) and mounts the versioned
// meeting API — request-id + fail-closed identity middleware plus the admission
// routes — backed by the MySQL store, Redis cooldown, seam HTTP clients, and the
// LiveKit minter.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/api"
	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/health"
	"github.com/Jerry-Xin/octo-meeting-service/internal/httpserver"
	"github.com/Jerry-Xin/octo-meeting-service/internal/livekit"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams/httpclient"
	"github.com/Jerry-Xin/octo-meeting-service/internal/storage"
)

// Build metadata, injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
)

// cooldownTTL bounds how long idle password-attempt state survives in Redis.
const cooldownTTL = 10 * time.Minute

// passTokenMaxTTL bounds how long pass-token keys linger in Redis.
const passTokenMaxTTL = time.Hour

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

	// Build the admission service from real collaborators and the fail-closed
	// auth seam used by the identity middleware.
	svc := buildService(cfg, db, redisClient, logger)
	auth := httpclient.NewAuthClient(seamOptions(cfg.Seams.Auth, cfg.Internal.ServiceToken))

	engine := newAPIEngine(cfg, metrics, readiness, svc, auth)

	apiSrv := httpserver.NewHTTPServer(cfg.HTTP, engine)
	metricsSrv := &http.Server{
		Addr:              cfg.HTTP.MetricsAddr,
		Handler:           metrics.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

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

// newAPIEngine assembles the gin engine with the operational surface plus the
// versioned API group guarded by request-id and fail-closed identity middleware,
// with the admission routes registered. This is the single wiring path used by
// both the running binary and the router test, so the test proves the real
// entrypoint exposes admission routes under the configured base path.
func newAPIEngine(cfg *config.Config, metrics *observability.Metrics, readiness *health.Registry, svc *api.Service, auth seams.Auth) *gin.Engine {
	return httpserver.NewEngine(httpserver.Deps{
		Config:        cfg,
		Metrics:       metrics,
		Health:        readiness,
		V1Middlewares: []gin.HandlerFunc{api.RequestID(), api.Identity(auth)},
		RegisterV1:    svc.Register,
	})
}

// buildService constructs the admission service from real collaborators. The
// meeting store is MySQL-backed and the cooldown hot path is Redis-backed; the
// pass-token and password-verifier stores remain in-memory this milestone (their
// durable backings land with the create/credential subsystem).
func buildService(cfg *config.Config, db *sql.DB, rc *redis.Client, logger *zap.Logger) *api.Service {
	acfg := api.DefaultConfig()
	acfg.LiveKitURL = cfg.LiveKit.URL

	return &api.Service{
		Store:         storage.NewMySQLStore(db, cfg.Credential.LookupSecret),
		ReadStore:     storage.NewMySQLReadStore(db),
		Space:         httpclient.NewSpaceClient(seamOptions(cfg.Seams.Space, cfg.Internal.ServiceToken)),
		Cooldown:      storage.NewRedisCooldownStore(rc, cooldownTTL),
		PassTokens:    storage.NewRedisPassTokenStore(rc, passTokenMaxTTL),
		Verifier:      storage.NewMySQLPasswordVerifier(db, cfg.Password.Pepper),
		Minter:        buildMinter(cfg.LiveKit, logger),
		Cfg:           acfg,
		Credentials:   buildCredentialMinter(cfg.Credential, logger),
		Argon:         password.DefaultArgon2Params(),
		Pepper:        cfg.Password.Pepper,
		PublicBaseURL: cfg.PublicBaseURL,
	}
}

// buildCredentialMinter derives the AES-256 envelope key from the configured
// secret (via SHA-256) and builds the credential minter. It returns nil when the
// credential secrets are unset, so meeting creation fails closed until configured.
func buildCredentialMinter(cfg config.CredentialConfig, logger *zap.Logger) *credential.Minter {
	if cfg.LookupSecret == "" || cfg.EnvelopeKey == "" {
		logger.Warn("credential secrets not configured; meeting creation is disabled")
		return nil
	}
	key := sha256.Sum256([]byte(cfg.EnvelopeKey))
	m, err := credential.NewMinter([]byte(cfg.LookupSecret), key[:])
	if err != nil {
		logger.Warn("credential minter init failed; meeting creation is disabled", zap.Error(err))
		return nil
	}
	return m
}

func seamOptions(ep config.SeamEndpoint, serviceToken string) httpclient.Options {
	return httpclient.Options{
		BaseURL:      ep.BaseURL,
		ServiceToken: serviceToken,
		HTTPClient:   &http.Client{Timeout: ep.Timeout},
	}
}

// buildMinter returns a LiveKit token minter, or an always-unavailable minter
// when credentials are not configured so finalize fails closed with
// MEETING_LIVEKIT_UNAVAILABLE rather than issuing an invalid token.
func buildMinter(cfg config.LiveKitConfig, logger *zap.Logger) api.TokenMinter {
	if cfg.APIKey == "" || cfg.APISecret == "" {
		logger.Warn("livekit credentials not configured; finalize will report media unavailable")
		return unavailableMinter{}
	}
	m, err := livekit.NewMinter(cfg.APIKey, cfg.APISecret, cfg.TokenTTL)
	if err != nil {
		logger.Warn("livekit minter init failed; finalize will report media unavailable", zap.Error(err))
		return unavailableMinter{}
	}
	return api.LiveKitMinter{M: m}
}

type unavailableMinter struct{}

func (unavailableMinter) MintAccess(_, _, _ string, _ map[string]string, _ time.Time) (string, error) {
	return "", errors.New("livekit not configured")
}
