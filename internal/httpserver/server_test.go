package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/health"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
)

func TestNewEngineMountsV1WithMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Env: "test", HTTP: config.HTTPConfig{BasePath: "/v1"}}

	var mwRan bool
	e := NewEngine(Deps{
		Config:  cfg,
		Logger:  zap.NewNop(),
		Metrics: observability.NewMetrics(),
		Health:  health.NewRegistry(time.Second),
		V1Middlewares: []gin.HandlerFunc{func(c *gin.Context) {
			mwRan = true
			c.Header("X-MW", "1")
			c.Next()
		}},
		RegisterV1: func(rg *gin.RouterGroup) {
			rg.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "pong" {
		t.Fatalf("mounted route: got %d %q", rec.Code, rec.Body.String())
	}
	if !mwRan || rec.Header().Get("X-MW") != "1" {
		t.Fatalf("v1 middleware did not run (ran=%v header=%q)", mwRan, rec.Header().Get("X-MW"))
	}

	// Health endpoints remain mounted at the root, outside the v1 group.
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz: got %d", rec.Code)
	}
}
