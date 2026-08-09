package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/admission"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// TokenMinter mints a LiveKit access token. It is an interface so the finalize
// path can be exercised (including the LiveKit-unavailable branch) without a
// real backend. Any error is treated as MEETING_LIVEKIT_UNAVAILABLE.
type TokenMinter interface {
	MintAccess(room, identity, role string, claims map[string]string, now time.Time) (string, error)
}

// Config carries the frozen time-window and policy knobs used by admission.
type Config struct {
	EarlyJoinWindow time.Duration
	ReconnectGrace  time.Duration
	PassTokenTTL    time.Duration
	Cooldown        password.Policy
	LiveKitURL      string
}

// DefaultConfig returns the approved defaults.
func DefaultConfig() Config {
	return Config{
		EarlyJoinWindow: meeting.DefaultEarlyJoinWindow,
		ReconnectGrace:  meeting.DefaultReconnectGrace,
		PassTokenTTL:    2 * time.Minute,
		Cooldown:        password.DefaultPolicy(),
	}
}

// Service holds the admission collaborators.
type Service struct {
	Store      repo.Store
	Space      seams.Space
	Cooldown   repo.CooldownStore
	PassTokens repo.PassTokenStore
	Verifier   repo.PasswordVerifier
	Minter     TokenMinter
	Now        func() time.Time
	Cfg        Config
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Register mounts the admission routes on the given (already identity-guarded)
// router group.
func (s *Service) Register(rg *gin.RouterGroup) {
	rg.POST("/meetings/admission/evaluate", s.Evaluate)
	rg.POST("/meetings/:meeting_id/password/verify", s.VerifyPassword)
	rg.POST("/meetings/:meeting_id/admission/finalize", s.Finalize)
}

type evaluateRequest struct {
	Source        string `json:"source"`
	MeetingID     string `json:"meeting_id"`
	MeetingNumber string `json:"meeting_number"`
	LinkToken     string `json:"link_token"`
}

type evaluateResponse struct {
	MeetingID           string `json:"meeting_id"`
	Status              string `json:"status"`
	PasswordRequired    bool   `json:"password_required"`
	PasswordChallengeID string `json:"password_challenge_id,omitempty"`
	AllowedToPrejoin    bool   `json:"allowed_to_prejoin"`
	Version             int64  `json:"version"`
}

// resolveCredential enforces "exactly one credential" and resolves the meeting.
// A missing/ambiguous/unresolvable credential collapses to CredentialInvalid so
// nothing about existence leaks.
func (s *Service) resolveCredential(ctx context.Context, req evaluateRequest) (repo.Meeting, *merr.Error) {
	var (
		kind  repo.CredentialKind
		value string
		count int
	)
	if req.MeetingID != "" {
		kind, value = repo.ByID, req.MeetingID
		count++
	}
	if req.MeetingNumber != "" {
		kind, value = repo.ByNumber, req.MeetingNumber
		count++
	}
	if req.LinkToken != "" {
		kind, value = repo.ByLink, req.LinkToken
		count++
	}
	if count != 1 {
		return repo.Meeting{}, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid.")
	}
	m, found, err := s.Store.Resolve(ctx, kind, value)
	if err != nil {
		return repo.Meeting{}, merr.New(merr.Internal, "An unexpected error occurred.")
	}
	if !found {
		return repo.Meeting{}, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid.")
	}
	return m, nil
}

// facts builds the oracle inputs for a meeting and caller.
func (s *Service) facts(ctx context.Context, m repo.Meeting, uid, orgID string, hasPass bool) (admission.MeetingFacts, admission.CallerFacts, error) {
	activeCount, err := s.Store.ActiveParticipantCount(ctx, m.MeetingID)
	if err != nil {
		return admission.MeetingFacts{}, admission.CallerFacts{}, err
	}
	removed, err := s.Store.IsRemoved(ctx, m.MeetingID, uid)
	if err != nil {
		return admission.MeetingFacts{}, admission.CallerFacts{}, err
	}
	invitee, err := s.Store.IsInvitee(ctx, m.MeetingID, uid)
	if err != nil {
		return admission.MeetingFacts{}, admission.CallerFacts{}, err
	}
	participant, err := s.Store.IsParticipant(ctx, m.MeetingID, uid)
	if err != nil {
		return admission.MeetingFacts{}, admission.CallerFacts{}, err
	}
	// Space membership is fail-closed: any seam error means "not a member".
	sameSpace, sErr := s.Space.IsMember(ctx, m.SpaceID, uid)
	if sErr != nil {
		sameSpace = false
	}

	within := true
	if m.Type == meeting.TypeScheduled && !m.ScheduledStartAt.IsZero() {
		within = meeting.WithinEarlyJoinWindow(s.now(), m.ScheduledStartAt, s.Cfg.EarlyJoinWindow)
	}

	mf := admission.MeetingFacts{
		Exists:                true,
		Ended:                 m.Status == meeting.StatusEnded,
		Cancelled:             m.Status == meeting.StatusCancelled,
		Locked:                m.Locked,
		Full:                  m.MaxParticipants > 0 && activeCount >= m.MaxParticipants,
		WithinEarlyJoinWindow: within,
		PasswordEnabled:       m.PasswordEnabled,
	}
	cf := admission.CallerFacts{
		SameSpaceActiveMember: sameSpace,
		IsCreator:             m.CreatorUID == uid,
		IsInvitee:             invitee,
		IsParticipant:         participant,
		Removed:               removed,
		HasValidPassToken:     hasPass,
	}
	return mf, cf, nil
}

// Evaluate handles POST /meetings/admission/evaluate.
func (s *Service) Evaluate(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	var req evaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid."))
		return
	}
	m, cerr := s.resolveCredential(c.Request.Context(), req)
	if cerr != nil {
		WriteError(c, cerr)
		return
	}
	hasPass, _ := s.PassTokens.ValidForUser(c.Request.Context(), m.MeetingID, p.UserID, s.now())
	mf, cf, err := s.facts(c.Request.Context(), m, p.UserID, p.OrgID, hasPass)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}

	d := admission.Evaluate(mf, cf)
	if !d.Eligible {
		WriteError(c, s.decisionError(d.Error, m))
		return
	}
	resp := evaluateResponse{
		MeetingID:        m.MeetingID,
		Status:           string(m.Status),
		PasswordRequired: d.PasswordRequired,
		AllowedToPrejoin: d.AllowedToPrejoin,
		Version:          m.Version,
	}
	if d.PasswordRequired {
		resp.PasswordChallengeID = newChallengeID()
	}
	WriteJSON(c, http.StatusOK, resp)
}

// decisionError attaches the safe details a step-1 error is allowed to carry.
func (s *Service) decisionError(code merr.Code, m repo.Meeting) *merr.Error {
	e := merr.New(code, "")
	switch code {
	case merr.TooEarly:
		if !m.ScheduledStartAt.IsZero() {
			earliest := meeting.EarliestJoinAt(m.ScheduledStartAt, s.Cfg.EarlyJoinWindow)
			e = e.WithDetail("earliest_join_at", earliest.UTC().Format(time.RFC3339))
		}
	case merr.Full:
		if m.MaxParticipants > 0 {
			e = e.WithDetail("max_participants", m.MaxParticipants)
		}
	}
	return e
}

type passwordVerifyRequest struct {
	Password            string `json:"password"`
	PasswordChallengeID string `json:"password_challenge_id"`
}

type passwordPassResponse struct {
	PasswordPassToken string `json:"password_pass_token"`
	ExpiresAt         string `json:"expires_at"`
	Version           int64  `json:"version"`
}

// VerifyPassword handles POST /meetings/:meeting_id/password/verify.
func (s *Service) VerifyPassword(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	meetingID := c.Param("meeting_id")
	ctx := c.Request.Context()

	// Security gate FIRST (blocker XIN-1803): resolve the meeting and apply the
	// same S-1/FD-27 oracle as evaluate/finalize BEFORE the body is parsed or the
	// verifier, cooldown, or pass-token store is touched. An unauthorized
	// cross-Space guess therefore gets an indistinguishable 404 and never learns
	// whether the meeting exists, is password-protected, or whether a password is
	// valid — closing the enumeration/oracle hole.
	m, found, err := s.Store.Resolve(ctx, repo.ByID, meetingID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if !found {
		WriteError(c, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid."))
		return
	}
	mf, cf, err := s.facts(ctx, m, p.UserID, p.OrgID, false)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if d := admission.Evaluate(mf, cf); !d.Eligible {
		WriteError(c, s.decisionError(d.Error, m))
		return
	}

	// Authorized to know the meeting exists: only now is it safe to parse the
	// password body and interact with the verifier/cooldown/pass-token stores.
	var req passwordVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, password.CheckFormat("")) // malformed body -> format error, not counted
		return
	}
	if ferr := password.CheckFormat(req.Password); ferr != nil {
		WriteError(c, ferr)
		return
	}

	state, err := s.Cooldown.Get(ctx, meetingID, p.UserID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	correct, err := s.Verifier.Verify(ctx, meetingID, req.Password)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	now := s.now()
	newState, outcome := s.Cfg.Cooldown.Verify(state, now, correct)
	if err := s.Cooldown.Put(ctx, meetingID, p.UserID, newState); err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}

	switch {
	case outcome.Success:
		exp := now.Add(s.Cfg.PassTokenTTL)
		token, err := s.PassTokens.Issue(ctx, meetingID, p.UserID, exp)
		if err != nil {
			WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
			return
		}
		WriteJSON(c, http.StatusOK, passwordPassResponse{
			PasswordPassToken: token,
			ExpiresAt:         exp.UTC().Format(time.RFC3339),
		})
	case outcome.Code == merr.PasswordCooldown:
		WriteError(c, merr.New(merr.PasswordCooldown, "Too many incorrect attempts; try again later.").
			WithDetail("retry_at", outcome.CooldownUntil.UTC().Format(time.RFC3339)))
	default:
		WriteError(c, merr.New(merr.PasswordInvalid, "The password is incorrect.").
			WithDetail("attempts_remaining", outcome.AttemptsRemaining))
	}
}

type finalizeRequest struct {
	PasswordPassToken string `json:"password_pass_token"`
	DeviceIDHash      string `json:"device_id_hash"`
}

type finalizeResponse struct {
	LiveKitURL           string `json:"livekit_url"`
	LiveKitToken         string `json:"livekit_token"`
	ParticipantSegmentID string `json:"participant_segment_id"`
	Role                 string `json:"role"`
	Version              int64  `json:"version"`
}

// Finalize handles POST /meetings/:meeting_id/admission/finalize.
func (s *Service) Finalize(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	meetingID := c.Param("meeting_id")
	var req finalizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid."))
		return
	}
	ctx := c.Request.Context()
	m, found, err := s.Store.Resolve(ctx, repo.ByID, meetingID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if !found {
		WriteError(c, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid."))
		return
	}

	// A supplied pass token is validated for this meeting+user.
	tokenValid := false
	if req.PasswordPassToken != "" {
		tokenValid, _ = s.PassTokens.Valid(ctx, req.PasswordPassToken, meetingID, p.UserID, s.now())
	}

	mf, cf, err := s.facts(ctx, m, p.UserID, p.OrgID, tokenValid)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	d := admission.Evaluate(mf, cf)
	if !d.Eligible {
		// A step-1 predicate changed since evaluate: return the concrete error.
		WriteError(c, s.decisionError(d.Error, m))
		return
	}
	if d.PasswordRequired {
		// Eligible but no valid pass: either the token expired or was never
		// obtained.
		if req.PasswordPassToken != "" {
			WriteError(c, merr.New(merr.PasswordPassExpired, "The password pass has expired; verify the password again."))
			return
		}
		WriteError(c, merr.New(merr.PasswordRequired, "A meeting password is required.").
			WithDetail("password_challenge_id", newChallengeID()))
		return
	}

	role := "M"
	if m.CreatorUID == p.UserID {
		role = "H"
	}
	segmentID := newSegmentID()
	room := "octo-meeting-" + m.MeetingID
	claims := map[string]string{
		"meeting_id":             m.MeetingID,
		"participant_segment_id": segmentID,
		"uid_hash":               shortHash(p.UserID),
		"role":                   role,
		"space_id_hash":          shortHash(m.SpaceID),
	}

	// Mint before consuming the pass token: a LiveKit failure must leave the
	// pass token valid so the client can replay finalize (FD-24/FD-32).
	tok, err := s.Minter.MintAccess(room, segmentID, role, claims, s.now())
	if err != nil {
		WriteError(c, merr.New(merr.LiveKitUnavailable, "The media service is temporarily unavailable.").
			WithDetail("retry_after", 2))
		return
	}

	// Success: consume the pass token (single-use-on-success) and start the
	// meeting live on first finalize.
	if req.PasswordPassToken != "" {
		_ = s.PassTokens.Consume(ctx, req.PasswordPassToken)
	}
	updated, err := s.Store.StartLive(ctx, m.MeetingID, s.now())
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}

	WriteJSON(c, http.StatusOK, finalizeResponse{
		LiveKitURL:           s.Cfg.LiveKitURL,
		LiveKitToken:         tok,
		ParticipantSegmentID: segmentID,
		Role:                 role,
		Version:              updated.Version,
	})
}

func newChallengeID() string { return "chal-" + randHex(8) }
func newSegmentID() string   { return "seg-" + randHex(12) }

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "0"
	}
	return hex.EncodeToString(buf)
}

// shortHash returns a non-reversible short identifier for token claims/logs.
func shortHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", sum[:8])
}
