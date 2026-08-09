package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type stubChecker struct {
	name string
	err  error
}

func (s stubChecker) Name() string                { return s.name }
func (s stubChecker) Check(context.Context) error { return s.err }

func init() { gin.SetMode(gin.TestMode) }

func doGet(h gin.HandlerFunc) *httptest.ResponseRecorder {
	r := gin.New()
	r.GET("/x", h)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestLiveness_AlwaysOK(t *testing.T) {
	reg := NewRegistry(time.Second)
	reg.Register(stubChecker{name: "db", err: errors.New("down")})
	if w := doGet(reg.Liveness); w.Code != http.StatusOK {
		t.Fatalf("liveness must be 200 regardless of deps, got %d", w.Code)
	}
}

func TestReadiness_AllOK(t *testing.T) {
	reg := NewRegistry(time.Second)
	reg.Register(stubChecker{name: "db"})
	reg.Register(stubChecker{name: "redis"})
	if w := doGet(reg.Readiness); w.Code != http.StatusOK {
		t.Fatalf("expected 200 when all deps ok, got %d", w.Code)
	}
}

func TestReadiness_OneDown(t *testing.T) {
	reg := NewRegistry(time.Second)
	reg.Register(stubChecker{name: "db"})
	reg.Register(stubChecker{name: "redis", err: errors.New("down")})
	if w := doGet(reg.Readiness); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when a dep is down, got %d", w.Code)
	}
}
