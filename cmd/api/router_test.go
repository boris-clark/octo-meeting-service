package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/api"
	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
	"github.com/Jerry-Xin/octo-meeting-service/internal/health"
	"github.com/Jerry-Xin/octo-meeting-service/internal/observability"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

type stubAuth struct{ good string }

func (a stubAuth) Authenticate(_ context.Context, bearer string) (*seams.Principal, error) {
	if bearer == a.good {
		return &seams.Principal{UserID: "u1", OrgID: "o1"}, nil
	}
	return nil, errors.New("invalid")
}

type stubSpace struct{}

func (stubSpace) IsMember(context.Context, string, string) (bool, error) { return false, nil }

type stubMinter struct{}

func (stubMinter) MintAccess(_, _, _ string, _ map[string]string, _ time.Time) (string, error) {
	return "lk", nil
}

// buildTestEngine assembles the engine exactly as run() does — via newAPIEngine
// with request-id + fail-closed identity and svc.Register — but with in-memory
// storage/seam doubles, so the test proves the real cmd/api wiring exposes the
// admission routes under the configured base path.
func buildTestEngine(basePath string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	svc := &api.Service{
		Store:      repo.NewMemStore(),
		Space:      stubSpace{},
		Cooldown:   repo.NewMemCooldownStore(),
		PassTokens: repo.NewMemPassTokenStore(),
		Verifier:   repo.NewMemPasswordVerifier(),
		Minter:     stubMinter{},
		Cfg:        api.DefaultConfig(),
	}
	cfg := &config.Config{Env: "test", HTTP: config.HTTPConfig{BasePath: basePath}}
	return newAPIEngine(cfg, observability.NewMetrics(), health.NewRegistry(time.Second), svc, stubAuth{good: "good"})
}

func request(t *testing.T, e *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("token", token)
	}
	req.Header.Set("X-Space-Id", "o1")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func codeOf(rec *httptest.ResponseRecorder) string {
	var env struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return env.Code
}

// TestRealEntrypointMountsAdmissionRoutes proves the binary's wiring — not just
// the api-package test harness — exposes the admission routes under the
// configured base path, guarded by request-id + fail-closed identity.
func TestRealEntrypointMountsAdmissionRoutes(t *testing.T) {
	const base = "/meeting/api/v1"
	e := buildTestEngine(base)

	// Every admission route is mounted: without a credential the fail-closed
	// identity middleware returns 401 (not gin's plain 404 for an absent route).
	for _, p := range []string{
		base + "/meetings/admission/evaluate",
		base + "/meetings/m1/password/verify",
		base + "/meetings/m1/admission/finalize",
	} {
		rec := request(t, e, http.MethodPost, p, "", map[string]any{})
		if rec.Code != http.StatusUnauthorized || codeOf(rec) != "MEETING_AUTH_REQUIRED" {
			t.Fatalf("%s: got %d %s, want 401 MEETING_AUTH_REQUIRED (route mounted + identity guarded)", p, rec.Code, codeOf(rec))
		}
	}

	// With a verified identity, evaluate reaches the handler (indistinguishable
	// 404 for an unknown meeting), proving the route is wired to the domain code.
	rec := request(t, e, http.MethodPost, base+"/meetings/admission/evaluate", "good",
		map[string]any{"source": "number", "meeting_number": "000000"})
	if rec.Code != http.StatusNotFound || codeOf(rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("authorized evaluate: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, codeOf(rec))
	}

	// A request id is issued/echoed by the wired middleware.
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("request-id middleware not wired at the entrypoint")
	}

	// Health stays at the root, outside the versioned group.
	h := request(t, e, http.MethodGet, "/healthz", "", nil)
	if h.Code != http.StatusOK {
		t.Fatalf("/healthz: got %d", h.Code)
	}

	// An unmounted path under the base still yields gin's plain 404 (no envelope),
	// confirming the 401s above are real mounted-route responses.
	miss := request(t, e, http.MethodGet, base+"/does-not-exist", "good", nil)
	if miss.Code != http.StatusNotFound || codeOf(miss) == "MEETING_AUTH_REQUIRED" {
		t.Fatalf("unmounted path: got %d %s", miss.Code, codeOf(miss))
	}
}

func TestEntrypointRespectsConfiguredBasePath(t *testing.T) {
	// A different base path must mount the same routes there and nowhere else.
	e := buildTestEngine("/v1")
	rec := request(t, e, http.MethodPost, "/v1/meetings/admission/evaluate", "", map[string]any{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("configured base path /v1: got %d, want 401", rec.Code)
	}
	// The old default gateway path is not mounted in this configuration.
	miss := request(t, e, http.MethodPost, "/meeting/api/v1/meetings/admission/evaluate", "", map[string]any{})
	if miss.Code != http.StatusNotFound {
		t.Fatalf("unconfigured base path: got %d, want 404", miss.Code)
	}
}
