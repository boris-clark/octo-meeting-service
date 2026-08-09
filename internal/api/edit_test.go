package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// editHarness wires the edit handler with a real credential minter + Argon and a
// host (alice) plus a member (bob).
type editHarness struct {
	engine *gin.Engine
	store  *repo.MemStore
}

func newEditHarness(t *testing.T, now time.Time) *editHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	minter, err := credential.NewMinter([]byte("lookup-secret"), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	store := repo.NewMemStore()
	svc := &Service{
		Store: store, Space: &fakeSpace{members: map[string]bool{}},
		Cooldown: repo.NewMemCooldownStore(), PassTokens: repo.NewMemPassTokenStore(),
		Verifier: repo.NewMemPasswordVerifier(), Minter: fakeMinter{token: "lk"},
		Now: func() time.Time { return now }, Cfg: DefaultConfig(),
		Credentials: minter, Argon: password.DefaultArgon2Params(), Pepper: "pepper-1",
	}
	auth := fakeAuth{byToken: map[string]*seams.Principal{
		"tok-alice": {UserID: "alice", OrgID: "space-1"},
		"tok-bob":   {UserID: "bob", OrgID: "space-1"},
	}}
	e := gin.New()
	v1 := e.Group("/v1")
	v1.Use(RequestID(), Identity(auth))
	svc.Register(v1)
	return &editHarness{engine: e, store: store}
}

func (h *editHarness) patch(t *testing.T, id, token string, body any, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPatch, "/v1/meetings/"+id, &buf)
	req.Header.Set("token", token)
	req.Header.Set("X-Space-Id", "space-1")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

func editSeed(h *editHarness, id string, status meeting.Status) {
	h.store.AddMeeting(repo.Meeting{
		MeetingID: id, SpaceID: "space-1", Type: meeting.TypeScheduled,
		Status: status, CreatorUID: "alice", HostUID: "alice", Version: 1,
	}, "", "")
	h.store.SetRoleDirect(id, "bob", "M")
}

func TestEditHostOnlyAndVersionBump(t *testing.T) {
	h := newEditHarness(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	editSeed(h, "m1", meeting.StatusScheduled)

	// A member cannot edit.
	if rec := h.patch(t, "m1", "tok-bob", map[string]any{"topic": "x"}, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("member edit: got %d, want 403", rec.Code)
	}
	// Host edits topic -> 200, version bumped 1 -> 2.
	rec := h.patch(t, "m1", "tok-alice", map[string]any{"topic": "new topic"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("host edit: got %d body=%s", rec.Code, rec.Body.String())
	}
	var r controlResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Version != 2 {
		t.Fatalf("version = %d, want 2", r.Version)
	}
}

func TestEditStaleVersionConflict(t *testing.T) {
	h := newEditHarness(t, time.Now())
	editSeed(h, "m2", meeting.StatusScheduled)
	rec := h.patch(t, "m2", "tok-alice", map[string]any{"topic": "x"}, "99")
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_VERSION_CONFLICT" {
		t.Fatalf("stale version: got %d %s", rec.Code, decodeCode(t, rec))
	}
}

func TestEditPasswordImmutableAfterLive(t *testing.T) {
	h := newEditHarness(t, time.Now())
	editSeed(h, "m3", meeting.StatusLive)
	rec := h.patch(t, "m3", "tok-alice",
		map[string]any{"password_op": map[string]any{"action": "set", "password": "424242"}}, "")
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_PASSWORD_IMMUTABLE" {
		t.Fatalf("post-live password: got %d %s, want 409 MEETING_PASSWORD_IMMUTABLE", rec.Code, decodeCode(t, rec))
	}
}

func TestEditPastTimeInvalid(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	h := newEditHarness(t, now)
	editSeed(h, "m4", meeting.StatusScheduled)
	rec := h.patch(t, "m4", "tok-alice",
		map[string]any{"scheduled_start_at": now.Add(-time.Hour).Format(time.RFC3339), "duration_minutes": 30}, "")
	if rec.Code != http.StatusUnprocessableEntity || decodeCode(t, rec) != "MEETING_TIME_INVALID" {
		t.Fatalf("past time edit: got %d %s", rec.Code, decodeCode(t, rec))
	}
}

func TestEditPasswordChangeBeforeLive(t *testing.T) {
	h := newEditHarness(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	editSeed(h, "m5", meeting.StatusScheduled)

	// Enable a password before live.
	rec := h.patch(t, "m5", "tok-alice",
		map[string]any{"password_op": map[string]any{"action": "set", "password": "424242"}}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("set password: got %d body=%s", rec.Code, rec.Body.String())
	}
	var r controlResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if !r.PasswordEnabled {
		t.Fatalf("password not enabled after set: %+v", r)
	}
	// Clearing it disables the password and bumps the version again.
	rec = h.patch(t, "m5", "tok-alice", map[string]any{"password_op": map[string]any{"action": "clear"}}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("clear password: got %d body=%s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.PasswordEnabled {
		t.Fatalf("password still enabled after clear: %+v", r)
	}
}
