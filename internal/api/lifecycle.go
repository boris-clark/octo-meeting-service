package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/authz"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/password"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

type quickCreateRequest struct {
	Topic    string `json:"topic"`
	Password string `json:"password"`
}

type scheduleRequest struct {
	Topic            string   `json:"topic"`
	ScheduledStartAt string   `json:"scheduled_start_at"`
	DurationMinutes  int      `json:"duration_minutes"`
	InviteeUIDs      []string `json:"invitee_uids"`
	Password         string   `json:"password"`
}

type meetingCreatedResponse struct {
	MeetingID       string `json:"meeting_id"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	MeetingNumber   string `json:"meeting_number"`
	JoinLink        string `json:"join_link"`
	PasswordEnabled bool   `json:"password_enabled"`
	Version         int64  `json:"version"`
}

// QuickCreate handles POST /meetings/quick-create.
func (s *Service) QuickCreate(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	var req quickCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = quickCreateRequest{}
	}
	if req.Password != "" {
		if ferr := password.CheckFormat(req.Password); ferr != nil {
			WriteError(c, ferr)
			return
		}
	}
	spaceID := c.GetHeader("X-Space-Id")
	now := s.now()

	// Explicit Idempotency-Key precedes the implicit space+creator+2s window.
	idemKey := c.GetHeader("Idempotency-Key")
	if idemKey == "" {
		idemKey = meeting.QuickCreateImplicitKey(spaceID, p.UserID, now)
	}
	fingerprint := payloadFingerprint(req.Topic, req.Password != "")

	rec := repo.Meeting{
		MeetingID:       s.newID(),
		SpaceID:         spaceID,
		Type:            meeting.TypeQuick,
		Status:          meeting.StatusScheduled,
		CreatorUID:      p.UserID,
		HostUID:         p.UserID,
		PasswordEnabled: req.Password != "",
		MaxParticipants: s.Cfg.MaxParticipants,
		Version:         1,
	}
	s.persistCreated(c, rec, req.Password, "quick_create", idemKey, fingerprint)
}

// Schedule handles POST /meetings.
func (s *Service) Schedule(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	var req scheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.TimeInvalid, "The scheduled time is invalid."))
		return
	}
	now := s.now()
	start, terr := time.Parse(time.RFC3339, req.ScheduledStartAt)
	if terr != nil || !start.After(now) || req.DurationMinutes < 1 {
		WriteError(c, merr.New(merr.TimeInvalid, "The scheduled time is invalid.").
			WithDetail("server_now", now.UTC().Format(time.RFC3339)))
		return
	}
	if req.Password != "" {
		if ferr := password.CheckFormat(req.Password); ferr != nil {
			WriteError(c, ferr)
			return
		}
	}
	spaceID := c.GetHeader("X-Space-Id")
	idemKey := c.GetHeader("Idempotency-Key") // scheduled create: explicit only
	fingerprint := payloadFingerprint(req.Topic+"|"+req.ScheduledStartAt, req.Password != "")

	rec := repo.Meeting{
		MeetingID:        s.newID(),
		SpaceID:          spaceID,
		Type:             meeting.TypeScheduled,
		Status:           meeting.StatusScheduled,
		CreatorUID:       p.UserID,
		HostUID:          p.UserID,
		ScheduledStartAt: start.UTC(),
		PasswordEnabled:  req.Password != "",
		MaxParticipants:  s.Cfg.MaxParticipants,
		Version:          1,
	}
	s.persistCreated(c, rec, req.Password, "schedule", idemKey, fingerprint)
}

// persistCreated mints credentials + optional verifier, persists the meeting
// under the idempotency guard, and writes the created response. The raw password
// is hashed to a non-reversible verifier and never persisted or logged.
func (s *Service) persistCreated(c *gin.Context, rec repo.Meeting, rawPassword, scope, idemKey, fingerprint string) {
	if s.Credentials == nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	number, err := credential.GenerateNumber()
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	link, err := credential.GenerateLinkToken()
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	numberCT, err := s.Credentials.Seal(number)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	linkCT, err := s.Credentials.Seal(link)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}

	in := repo.CreateInput{
		Meeting:            rec,
		Number:             number,
		LinkToken:          link,
		NumberCiphertext:   numberCT,
		LinkCiphertext:     linkCT,
		IdempotencyScope:   scope,
		IdempotencyKey:     idemKey,
		PayloadFingerprint: fingerprint,
	}
	if rawPassword != "" {
		encoded, herr := s.Argon.Hash(rawPassword, s.Pepper)
		if herr != nil {
			WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
			return
		}
		in.Verifier = &repo.VerifierInput{
			Algorithm:  password.Algorithm,
			ParamsJSON: `{}`,
			SaltID:     "inline",
			PepperRef:  "configured",
			Verifier:   encoded,
		}
	}

	result, err := s.Store.CreateMeeting(c.Request.Context(), in)
	if err == repo.ErrIdempotencyConflict {
		WriteError(c, merr.New(merr.IdempotencyConflict, "The idempotency key was reused with a different request."))
		return
	}
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}

	// Determine the credentials to echo. On a fresh create these are the values
	// just minted. On an idempotent replay we return the ORIGINAL persisted
	// credentials (decrypted from the stored ciphertext) so the caller gets a
	// meeting number and join link that actually resolve — never freshly-minted
	// values that were never persisted.
	respNumber, respLink := number, link
	if result.Replayed {
		origNumber, oerr := s.Credentials.Open(result.NumberCiphertext)
		origLink, lerr := s.Credentials.Open(result.LinkCiphertext)
		if oerr != nil || lerr != nil {
			WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
			return
		}
		respNumber, respLink = origNumber, origLink
	}

	WriteJSON(c, http.StatusOK, meetingCreatedResponse{
		MeetingID:       result.Meeting.MeetingID,
		Type:            string(result.Meeting.Type),
		Status:          string(result.Meeting.Status),
		MeetingNumber:   respNumber,
		JoinLink:        s.joinLink(respLink),
		PasswordEnabled: result.Meeting.PasswordEnabled,
		Version:         result.Meeting.Version,
	})
}

func (s *Service) joinLink(linkToken string) string {
	return s.PublicBaseURL + "/meeting/join/" + linkToken
}

// payloadFingerprint is a stable, non-sensitive digest of the idempotency-
// relevant request fields (never the raw password — only whether one is set).
func payloadFingerprint(topic string, passwordEnabled bool) string {
	flag := "0"
	if passwordEnabled {
		flag = "1"
	}
	sum := sha256.Sum256([]byte(topic + "|" + flag))
	return hex.EncodeToString(sum[:])
}

type editRequest struct {
	Topic            *string `json:"topic"`
	ScheduledStartAt *string `json:"scheduled_start_at"`
	DurationMinutes  *int    `json:"duration_minutes"`
	PasswordOp       *struct {
		Action   string `json:"action"` // "set" | "clear"
		Password string `json:"password"`
	} `json:"password_op"`
}

// Edit handles PATCH /meetings/:meeting_id (host, before live). It mutates
// topic/time/duration and/or the password under the same host-authorization,
// If-Match version, and server-clock time validation as create/cancel. The
// frozen contract guard applies: a password change after the meeting is live
// returns MEETING_PASSWORD_IMMUTABLE.
func (s *Service) Edit(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	var req editRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.Forbidden, "Invalid edit request."))
		return
	}
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if !authz.CanEditOrCancel(role) {
		WriteError(c, merr.New(merr.Forbidden, "Only the host may edit the meeting.").WithDetail("required_role", "H"))
		return
	}

	ctx := c.Request.Context()
	m, found, err := s.Store.Resolve(ctx, repo.ByID, meetingID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if !found {
		WriteError(c, merr.New(merr.Forbidden, "You do not have permission to perform this action."))
		return
	}

	// Frozen guard: the password is immutable once the meeting is live (or
	// otherwise no longer scheduled).
	if req.PasswordOp != nil && m.Status != meeting.StatusScheduled {
		WriteError(c, merr.New(merr.PasswordImmutable, "The password cannot be changed after the meeting is live.").
			WithDetail("status", string(m.Status)))
		return
	}
	fieldEdit := req.Topic != nil || req.ScheduledStartAt != nil || req.DurationMinutes != nil
	if (fieldEdit || req.PasswordOp != nil) && m.Status != meeting.StatusScheduled {
		WriteError(c, merr.New(merr.Forbidden, "The meeting can no longer be edited."))
		return
	}

	now := s.now()
	in := repo.EditInput{Topic: req.Topic, DurationMinutes: req.DurationMinutes}
	if req.ScheduledStartAt != nil {
		start, terr := time.Parse(time.RFC3339, *req.ScheduledStartAt)
		if terr != nil || !start.After(now) {
			WriteError(c, merr.New(merr.TimeInvalid, "The scheduled time is invalid.").
				WithDetail("server_now", now.UTC().Format(time.RFC3339)))
			return
		}
		in.ScheduledStart = &start
	}
	if req.DurationMinutes != nil && *req.DurationMinutes < 1 {
		WriteError(c, merr.New(merr.TimeInvalid, "The duration is invalid."))
		return
	}
	if req.PasswordOp != nil {
		switch req.PasswordOp.Action {
		case "clear":
			in.Password = &repo.PasswordOp{Clear: true}
		case "set":
			if ferr := password.CheckFormat(req.PasswordOp.Password); ferr != nil {
				WriteError(c, ferr)
				return
			}
			encoded, herr := s.Argon.Hash(req.PasswordOp.Password, s.Pepper)
			if herr != nil {
				WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
				return
			}
			in.Password = &repo.PasswordOp{Verifier: &repo.VerifierInput{
				Algorithm: password.Algorithm, ParamsJSON: "{}", SaltID: "inline",
				PepperRef: "configured", Verifier: encoded,
			}}
		default:
			WriteError(c, merr.New(merr.Forbidden, "Invalid password operation."))
			return
		}
	}

	updated, err := s.Store.EditScheduled(ctx, meetingID, in, ifMatch(c))
	if err != nil {
		mapControlError(c, err)
		return
	}
	WriteJSON(c, http.StatusOK, summaryOf(updated))
}
