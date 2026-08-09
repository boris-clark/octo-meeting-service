package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// createHarness wires the create + admission routes with a real credential
// minter over the in-memory store.
type createHarness struct {
	engine *gin.Engine
	store  *repo.MemStore
	space  *fakeSpace
}

func newCreateHarness(t *testing.T, now time.Time) *createHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	minter, err := credential.NewMinter([]byte("lookup-secret"), bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	store := repo.NewMemStore()
	space := &fakeSpace{members: map[string]bool{}}
	var seq int
	svc := &Service{
		Store:       store,
		Space:       space,
		Cooldown:    repo.NewMemCooldownStore(),
		PassTokens:  repo.NewMemPassTokenStore(),
		Verifier:    repo.NewMemPasswordVerifier(),
		Minter:      fakeMinter{token: "lk"},
		Now:         func() time.Time { return now },
		Cfg:         DefaultConfig(),
		Credentials: minter,
		Argon:       password.DefaultArgon2Params(),
		Pepper:      "pepper-1",
		NewID:       func() string { seq++; return "mtg-" + strconv.Itoa(seq) },
	}
	auth := fakeAuth{byToken: map[string]*seams.Principal{"tok-alice": {UserID: "alice", OrgID: "space-1"}}}
	e := gin.New()
	v1 := e.Group("/v1")
	v1.Use(RequestID(), Identity(auth))
	svc.Register(v1)
	return &createHarness{engine: e, store: store, space: space}
}

func (h *createHarness) post(t *testing.T, path, token string, body any, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	if token != "" {
		req.Header.Set("token", token)
	}
	req.Header.Set("X-Space-Id", "space-1")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

func decodeCreated(t *testing.T, rec *httptest.ResponseRecorder) meetingCreatedResponse {
	t.Helper()
	var r meetingCreatedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	return r
}

func TestQuickCreateMintsCredentials(t *testing.T) {
	h := newCreateHarness(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	rec := h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"topic": "standup"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	r := decodeCreated(t, rec)
	if r.Type != "quick" || r.Status != "scheduled" || r.Version != 1 {
		t.Fatalf("unexpected: %+v", r)
	}
	if len(r.MeetingNumber) != credential.NumberDigits {
		t.Fatalf("meeting number not %d digits: %q", credential.NumberDigits, r.MeetingNumber)
	}
	if r.JoinLink == "" || r.PasswordEnabled {
		t.Fatalf("unexpected join_link/password: %+v", r)
	}
	// The raw password/link must never be exposed as a stored plaintext; the
	// response join link carries the token but nothing else leaks.
}

func TestQuickCreateThenEvaluateByNumber(t *testing.T) {
	h := newCreateHarness(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	h.space.members["space-1|alice"] = true

	rec := h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"topic": "sync"}, nil)
	num := decodeCreated(t, rec).MeetingNumber

	// The freshly created meeting resolves by number through admission evaluate.
	ev := h.post(t, "/v1/meetings/admission/evaluate", "tok-alice",
		map[string]any{"source": "number", "meeting_number": num}, nil)
	if ev.Code != http.StatusOK {
		t.Fatalf("evaluate after create: got %d body=%s", ev.Code, ev.Body.String())
	}
	var evr evaluateResponse
	_ = json.Unmarshal(ev.Body.Bytes(), &evr)
	if !evr.AllowedToPrejoin || evr.PasswordRequired {
		t.Fatalf("no-password meeting should allow prejoin: %+v", evr)
	}
}

func TestQuickCreatePasswordFormat(t *testing.T) {
	h := newCreateHarness(t, time.Now())
	rec := h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"password": "abc"}, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad password format: got %d", rec.Code)
	}
}

func TestQuickCreateIdempotency(t *testing.T) {
	h := newCreateHarness(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC))
	h.space.members["space-1|alice"] = true
	hdr := map[string]string{"Idempotency-Key": "req-1"}

	a := decodeCreated(t, h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"topic": "x"}, hdr))
	b := decodeCreated(t, h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"topic": "x"}, hdr))
	if a.MeetingID != b.MeetingID {
		t.Fatalf("same key+payload must replay first result: %q vs %q", a.MeetingID, b.MeetingID)
	}
	// Blocker XIN-1806#1: the replay must echo the ORIGINAL credentials, not a
	// freshly-minted number that was never persisted.
	if b.MeetingNumber != a.MeetingNumber {
		t.Fatalf("replay number %q != original %q", b.MeetingNumber, a.MeetingNumber)
	}
	if b.JoinLink != a.JoinLink || b.JoinLink == "" {
		t.Fatalf("replay join link %q != original %q", b.JoinLink, a.JoinLink)
	}
	// And the replayed number actually resolves through admission evaluate.
	ev := h.post(t, "/v1/meetings/admission/evaluate", "tok-alice",
		map[string]any{"source": "number", "meeting_number": b.MeetingNumber}, nil)
	if ev.Code != http.StatusOK {
		t.Fatalf("replayed number must resolve: got %d body=%s", ev.Code, ev.Body.String())
	}

	// Same key, different payload -> conflict.
	conflict := h.post(t, "/v1/meetings/quick-create", "tok-alice", map[string]any{"topic": "y"}, hdr)
	if conflict.Code != http.StatusConflict || decodeCode(t, conflict) != "MEETING_IDEMPOTENCY_CONFLICT" {
		t.Fatalf("conflict expected: got %d %s", conflict.Code, decodeCode(t, conflict))
	}
}

func TestScheduleTimeValidation(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	h := newCreateHarness(t, now)

	// Past start -> MEETING_TIME_INVALID.
	past := h.post(t, "/v1/meetings", "tok-alice", map[string]any{
		"topic": "m", "scheduled_start_at": now.Add(-time.Hour).Format(time.RFC3339), "duration_minutes": 30,
	}, nil)
	if past.Code != http.StatusUnprocessableEntity || decodeCode(t, past) != "MEETING_TIME_INVALID" {
		t.Fatalf("past time: got %d %s", past.Code, decodeCode(t, past))
	}

	// Future start -> created, type=scheduled.
	ok := h.post(t, "/v1/meetings", "tok-alice", map[string]any{
		"topic": "m", "scheduled_start_at": now.Add(time.Hour).Format(time.RFC3339), "duration_minutes": 30,
	}, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("future schedule: got %d body=%s", ok.Code, ok.Body.String())
	}
	if r := decodeCreated(t, ok); r.Type != "scheduled" {
		t.Fatalf("type = %q, want scheduled", r.Type)
	}
}
