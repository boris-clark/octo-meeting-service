package api

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

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// --- test doubles ---

type fakeAuth struct{ byToken map[string]*seams.Principal }

func (f fakeAuth) Authenticate(_ context.Context, bearer string) (*seams.Principal, error) {
	if p, ok := f.byToken[bearer]; ok {
		return p, nil
	}
	return nil, errors.New("invalid")
}

type fakeSpace struct{ members map[string]bool } // key: org|uid

func (f fakeSpace) IsMember(_ context.Context, orgID, uid string) (bool, error) {
	return f.members[orgID+"|"+uid], nil
}

type fakeMinter struct {
	token string
	err   error
}

func (f fakeMinter) MintAccess(_, _, _ string, _ map[string]string, _ time.Time) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

// harness wires the service into a gin engine with request-id + fail-closed
// identity, exactly as the server mounts it.
type harness struct {
	engine   *gin.Engine
	store    *repo.MemStore
	space    *fakeSpace
	verifier *repo.MemPasswordVerifier
	svc      *Service
}

func newHarness(t *testing.T, minter TokenMinter, now time.Time) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := repo.NewMemStore()
	space := &fakeSpace{members: map[string]bool{}}
	verifier := repo.NewMemPasswordVerifier()
	svc := &Service{
		Store:      store,
		Space:      space,
		Cooldown:   repo.NewMemCooldownStore(),
		PassTokens: repo.NewMemPassTokenStore(),
		Verifier:   verifier,
		Minter:     minter,
		Now:        func() time.Time { return now },
		Cfg:        DefaultConfig(),
	}
	auth := fakeAuth{byToken: map[string]*seams.Principal{
		"tok-alice": {UserID: "alice", OrgID: "space-1"},
		"tok-bob":   {UserID: "bob", OrgID: "space-2"},
	}}
	e := gin.New()
	v1 := e.Group("/v1")
	v1.Use(RequestID(), Identity(auth))
	svc.Register(v1)
	return &harness{engine: e, store: store, space: space, verifier: verifier, svc: svc}
}

func (h *harness) do(t *testing.T, method, path, token string, body any, extraHeaders map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("token", token)
	}
	req.Header.Set("X-Space-Id", "space-1")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

func decodeCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return env.Code
}

// --- tests ---

func TestIdentityFailClosed(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())

	// No credential -> 401, even if a spoofed x-user-id is present.
	rec := h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "",
		map[string]any{"source": "number", "meeting_number": "123456"},
		map[string]string{"x-user-id": "admin", "x-org-id": "space-1"})
	if rec.Code != http.StatusUnauthorized || decodeCode(t, rec) != "MEETING_AUTH_REQUIRED" {
		t.Fatalf("spoofed identity: got %d %s, want 401 MEETING_AUTH_REQUIRED", rec.Code, decodeCode(t, rec))
	}

	// Invalid token -> 401.
	rec = h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "tok-nope",
		map[string]any{"source": "number", "meeting_number": "123456"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: got %d, want 401", rec.Code)
	}
}

func TestEvaluateCrossSpaceEnumerationReturns404(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	// Meeting in space-1; caller bob is in space-2 and is not creator/invitee.
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m1", SpaceID: "space-1", Type: meeting.TypeScheduled,
		Status: meeting.StatusEnded, CreatorUID: "alice", Version: 1,
	}, "654321", "")

	// Cross-Space guesser must get an indistinguishable 404 even though the
	// meeting is actually ended.
	rec := h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "tok-bob",
		map[string]any{"source": "number", "meeting_number": "654321"}, nil)
	if rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("cross-space: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}

	// A totally unknown number is identical.
	rec = h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "tok-bob",
		map[string]any{"source": "number", "meeting_number": "000000"}, nil)
	if rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("unknown number: got %d %s, want 404", rec.Code, decodeCode(t, rec))
	}
}

func TestEvaluateEligiblePasswordDisposition(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	h.space.members["space-1|alice"] = true
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m2", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "carol", PasswordEnabled: true, Version: 3,
	}, "222222", "")

	rec := h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "tok-alice",
		map[string]any{"source": "number", "meeting_number": "222222"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("eligible: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp evaluateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.PasswordRequired || resp.AllowedToPrejoin || resp.PasswordChallengeID == "" {
		t.Fatalf("password disposition wrong: %+v", resp)
	}
	if resp.MeetingID != "m2" || resp.Version != 3 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestPasswordCooldownOverHTTP(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, fakeMinter{token: "lk"}, now)
	h.space.members["space-1|alice"] = true
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m3", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "carol", PasswordEnabled: true, Version: 1,
	}, "333333", "")
	h.verifier.Set("m3", "424242")

	// Format failure is not counted.
	rec := h.do(t, http.MethodPost, "/v1/meetings/m3/password/verify", "tok-alice",
		map[string]any{"password": "12ab", "password_challenge_id": "c"}, nil)
	if rec.Code != http.StatusUnprocessableEntity || decodeCode(t, rec) != "MEETING_PASSWORD_FORMAT_INVALID" {
		t.Fatalf("format: got %d %s", rec.Code, decodeCode(t, rec))
	}

	// Five wrong attempts -> cooldown on the 5th.
	for i := 1; i <= 4; i++ {
		rec = h.do(t, http.MethodPost, "/v1/meetings/m3/password/verify", "tok-alice",
			map[string]any{"password": "000000", "password_challenge_id": "c"}, nil)
		if rec.Code != http.StatusUnauthorized || decodeCode(t, rec) != "MEETING_PASSWORD_INVALID" {
			t.Fatalf("attempt %d: got %d %s", i, rec.Code, decodeCode(t, rec))
		}
	}
	rec = h.do(t, http.MethodPost, "/v1/meetings/m3/password/verify", "tok-alice",
		map[string]any{"password": "000000", "password_challenge_id": "c"}, nil)
	if rec.Code != http.StatusTooManyRequests || decodeCode(t, rec) != "MEETING_PASSWORD_COOLDOWN" {
		t.Fatalf("5th: got %d %s, want 429 cooldown", rec.Code, decodeCode(t, rec))
	}
}

func TestFinalizeLiveKitUnavailableRetainsPassToken(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, fakeMinter{err: errors.New("livekit down")}, now)
	h.space.members["space-1|alice"] = true
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m4", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "carol", PasswordEnabled: true, Version: 1,
	}, "444444", "")
	h.verifier.Set("m4", "424242")

	// Get a pass token.
	rec := h.do(t, http.MethodPost, "/v1/meetings/m4/password/verify", "tok-alice",
		map[string]any{"password": "424242", "password_challenge_id": "c"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: got %d body=%s", rec.Code, rec.Body.String())
	}
	var pass passwordPassResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &pass)
	if pass.PasswordPassToken == "" {
		t.Fatal("no pass token issued")
	}

	// Finalize with LiveKit down -> 503, pass token NOT consumed.
	rec = h.do(t, http.MethodPost, "/v1/meetings/m4/admission/finalize", "tok-alice",
		map[string]any{"password_pass_token": pass.PasswordPassToken, "device_id_hash": "dev1"}, nil)
	if rec.Code != http.StatusServiceUnavailable || decodeCode(t, rec) != "MEETING_LIVEKIT_UNAVAILABLE" {
		t.Fatalf("livekit down: got %d %s, want 503", rec.Code, decodeCode(t, rec))
	}

	// The token is still valid for replay.
	ok, _ := h.svc.PassTokens.Valid(context.Background(), pass.PasswordPassToken, "m4", "alice", now)
	if !ok {
		t.Fatal("pass token must survive a retryable LiveKit failure")
	}
}

func TestFinalizeSuccessMintsTokenAndGoesLive(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	h := newHarness(t, fakeMinter{token: "lk-token-xyz"}, now)
	h.space.members["space-1|alice"] = true
	// alice is the creator -> exempt from password, role H.
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m5", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "alice", PasswordEnabled: true, Version: 1,
	}, "555555", "")

	rec := h.do(t, http.MethodPost, "/v1/meetings/m5/admission/finalize", "tok-alice",
		map[string]any{"device_id_hash": "dev1"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("finalize: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp finalizeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.LiveKitToken != "lk-token-xyz" || resp.Role != "H" || resp.ParticipantSegmentID == "" {
		t.Fatalf("finalize response wrong: %+v", resp)
	}
	// First finalize started the meeting live.
	m, _, _ := h.store.Resolve(context.Background(), repo.ByID, "m5")
	if m.Status != meeting.StatusLive || m.ActualStartAt.IsZero() {
		t.Fatalf("meeting not live: %+v", m)
	}
	if resp.Version <= 1 {
		t.Fatalf("version not bumped on start-live: %d", resp.Version)
	}
}

func TestRequestIDEchoedOnError(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	rec := h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "",
		map[string]any{"source": "number"}, map[string]string{"X-Request-Id": "rid-123"})
	if got := rec.Header().Get("X-Request-Id"); got != "rid-123" {
		t.Fatalf("request id not echoed: %q", got)
	}
	var env struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.RequestID != "rid-123" {
		t.Fatalf("request id not in envelope: %q", env.RequestID)
	}
}

// Guard against accidental use of the default policy's zero value.
func TestDefaultConfigPolicy(t *testing.T) {
	if DefaultConfig().Cooldown.MaxAttempts != password.DefaultMaxAttempts {
		t.Fatal("default cooldown policy not set")
	}
}

// --- blocker XIN-1803: VerifyPassword must gate before touching stores ---

// counting spies assert that the verifier/cooldown/pass-token stores are NOT
// touched when an unauthorized caller hits password/verify.
type spyCooldown struct {
	inner      repo.CooldownStore
	gets, puts int
}

func (s *spyCooldown) Get(ctx context.Context, m, u string) (password.State, error) {
	s.gets++
	return s.inner.Get(ctx, m, u)
}
func (s *spyCooldown) Put(ctx context.Context, m, u string, st password.State) error {
	s.puts++
	return s.inner.Put(ctx, m, u, st)
}

type spyVerifier struct {
	inner repo.PasswordVerifier
	calls int
}

func (s *spyVerifier) Verify(ctx context.Context, m, raw string) (bool, error) {
	s.calls++
	return s.inner.Verify(ctx, m, raw)
}

type spyPassTokens struct {
	inner  repo.PassTokenStore
	issues int
}

func (s *spyPassTokens) Issue(ctx context.Context, m, u string, exp time.Time) (string, error) {
	s.issues++
	return s.inner.Issue(ctx, m, u, exp)
}
func (s *spyPassTokens) Valid(ctx context.Context, t, m, u string, now time.Time) (bool, error) {
	return s.inner.Valid(ctx, t, m, u, now)
}
func (s *spyPassTokens) ValidForUser(ctx context.Context, m, u string, now time.Time) (bool, error) {
	return s.inner.ValidForUser(ctx, m, u, now)
}
func (s *spyPassTokens) Consume(ctx context.Context, t string) error {
	return s.inner.Consume(ctx, t)
}

func newSpyHarness(t *testing.T) (*harness, *spyCooldown, *spyVerifier, *spyPassTokens) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := repo.NewMemStore()
	space := &fakeSpace{members: map[string]bool{}}
	memVerifier := repo.NewMemPasswordVerifier()
	verifier := &spyVerifier{inner: memVerifier}
	cooldown := &spyCooldown{inner: repo.NewMemCooldownStore()}
	tokens := &spyPassTokens{inner: repo.NewMemPassTokenStore()}
	svc := &Service{
		Store: store, Space: space, Cooldown: cooldown, PassTokens: tokens,
		Verifier: verifier, Minter: fakeMinter{token: "lk"},
		Now: func() time.Time { return time.Unix(1_760_000_000, 0).UTC() }, Cfg: DefaultConfig(),
	}
	auth := fakeAuth{byToken: map[string]*seams.Principal{
		"tok-alice": {UserID: "alice", OrgID: "space-1"},
		"tok-bob":   {UserID: "bob", OrgID: "space-2"},
	}}
	e := gin.New()
	v1 := e.Group("/v1")
	v1.Use(RequestID(), Identity(auth))
	svc.Register(v1)
	return &harness{engine: e, store: store, space: space, verifier: memVerifier, svc: svc}, cooldown, verifier, tokens
}

func TestVerifyPasswordUnauthorizedIsIndistinguishable404(t *testing.T) {
	h, cooldown, verifier, tokens := newSpyHarness(t)
	// Password-protected meeting in space-1; bob (space-2, not creator/invitee/
	// participant) is unauthorized to know it exists.
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "secret", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "alice", PasswordEnabled: true, Version: 1,
	}, "999999", "")

	rec := h.do(t, http.MethodPost, "/v1/meetings/secret/password/verify", "tok-bob",
		map[string]any{"password": "123456", "password_challenge_id": "c"}, nil)

	// Indistinguishable from a non-existent meeting.
	if rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("unauthorized verify: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}

	// A verify against a meeting that does not exist at all returns the same.
	rec2 := h.do(t, http.MethodPost, "/v1/meetings/nope/password/verify", "tok-bob",
		map[string]any{"password": "123456", "password_challenge_id": "c"}, nil)
	if rec2.Code != rec.Code || decodeCode(t, rec2) != decodeCode(t, rec) {
		t.Fatalf("existent-vs-nonexistent distinguishable: %d/%s vs %d/%s",
			rec.Code, decodeCode(t, rec), rec2.Code, decodeCode(t, rec2))
	}

	// Crucially, no verifier/cooldown/pass-token interaction occurred.
	if verifier.calls != 0 {
		t.Errorf("verifier touched %d times for unauthorized caller", verifier.calls)
	}
	if cooldown.gets != 0 || cooldown.puts != 0 {
		t.Errorf("cooldown touched (gets=%d puts=%d) for unauthorized caller", cooldown.gets, cooldown.puts)
	}
	if tokens.issues != 0 {
		t.Errorf("pass token issued %d times for unauthorized caller", tokens.issues)
	}
}

func TestVerifyPasswordAuthorizedReachesVerifier(t *testing.T) {
	h, cooldown, verifier, tokens := newSpyHarness(t)
	h.space.members["space-1|alice"] = true
	h.store.AddMeeting(repo.Meeting{
		MeetingID: "m", SpaceID: "space-1", Type: meeting.TypeQuick,
		Status: meeting.StatusScheduled, CreatorUID: "carol", PasswordEnabled: true, Version: 1,
	}, "111111", "")
	h.store.SetParticipant("m", "alice") // authorized to know it exists
	h.verifier.Set("m", "424242")

	rec := h.do(t, http.MethodPost, "/v1/meetings/m/password/verify", "tok-alice",
		map[string]any{"password": "424242", "password_challenge_id": "c"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized verify: got %d body=%s", rec.Code, rec.Body.String())
	}
	if verifier.calls != 1 || cooldown.gets != 1 || tokens.issues != 1 {
		t.Fatalf("authorized path did not exercise stores: verifier=%d cooldown.gets=%d issues=%d",
			verifier.calls, cooldown.gets, tokens.issues)
	}
}
