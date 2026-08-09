// Package httpserver builds the Gin engine and the graceful HTTP servers for
// the API entrypoint. It mounts only operational routes in the bootstrap;
// domain routes are registered later under the configured base path.
package httpserver

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/health"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
)

// Deps are the collaborators the router needs.
type Deps struct {
	Config  *config.Config
	Logger  *zap.Logger
	Metrics *observability.Metrics
	Health  *health.Registry
	// V1Middlewares are applied to the versioned API group in order (e.g. request
	// id then fail-closed identity).
	V1Middlewares []gin.HandlerFunc
	// RegisterV1 mounts domain routes on the versioned API group. Nil in the
	// bootstrap leaves the group empty.
	RegisterV1 func(rg *gin.RouterGroup)
}

// NewEngine builds the Gin engine with baseline middleware and operational
// routes. Health endpoints live at the root; the versioned API is mounted under
// the configured base path (e.g. /v1) and is empty until domain work lands.
func NewEngine(d Deps) *gin.Engine {
	if d.Config.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	e := gin.New()
	_ = e.SetTrustedProxies(d.Config.HTTP.TrustedProxies)

	e.Use(gin.Recovery())
	e.Use(requestMetrics(d.Metrics))

	e.GET("/healthz", d.Health.Liveness)
	e.GET("/readyz", d.Health.Readiness)

	// Versioned API group. Middlewares (request id, fail-closed identity) apply
	// to every domain route; the group is empty unless RegisterV1 is provided.
	v1 := e.Group(d.Config.HTTP.BasePath)
	for _, mw := range d.V1Middlewares {
		v1.Use(mw)
	}
	if d.RegisterV1 != nil {
		d.RegisterV1(v1)
	}

	return e
}

// requestMetrics records request counts and latency using the matched route
// template (never the raw path) to keep cardinality bounded.
func requestMetrics(m *observability.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		m.HTTPRequests.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Inc()
		m.HTTPDuration.WithLabelValues(c.Request.Method, route).Observe(time.Since(start).Seconds())
	}
}

// NewHTTPServer wraps an http.Handler with the configured timeouts.
func NewHTTPServer(cfg config.HTTPConfig, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
	}
}

// Shutdown gracefully stops a server within the grace period.
func Shutdown(srv *http.Server, grace time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	return srv.Shutdown(ctx)
}
