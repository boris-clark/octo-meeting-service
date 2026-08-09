package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/authz"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// controlResponse is the compact summary returned by control mutations.
type controlResponse struct {
	MeetingID string `json:"meeting_id"`
	Status    string `json:"status"`
	Locked    bool   `json:"locked"`
	Version   int64  `json:"version"`
}

func summaryOf(m repo.Meeting) controlResponse {
	return controlResponse{MeetingID: m.MeetingID, Status: string(m.Status), Locked: m.Locked, Version: m.Version}
}

// ifMatch parses the optional If-Match version header (0 = no check).
func ifMatch(c *gin.Context) int64 {
	v, _ := strconv.ParseInt(c.GetHeader("If-Match"), 10, 64)
	return v
}

// actorRole resolves the caller's control role, failing closed to FORBIDDEN when
// they are not a participant of (or host of) the meeting. A non-existent meeting
// is indistinguishable from "not authorized" here, so existence does not leak to
// non-participants.
func (s *Service) actorRole(c *gin.Context, meetingID, uid string) (authz.Role, bool) {
	role, ok, err := s.Store.ParticipantRole(c.Request.Context(), meetingID, uid)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return "", false
	}
	if !ok {
		WriteError(c, merr.New(merr.Forbidden, "You do not have permission to perform this action."))
		return "", false
	}
	return authz.Role(role), true
}

// mapControlError renders a repo control error to the frozen taxonomy.
func mapControlError(c *gin.Context, err error) {
	switch err {
	case repo.ErrVersionConflict:
		WriteError(c, merr.New(merr.VersionConflict, "The meeting was modified; reload and retry."))
	case repo.ErrInvalidTransition:
		WriteError(c, merr.New(merr.Forbidden, "The meeting is not in a state that allows this action."))
	case repo.ErrNotFound:
		WriteError(c, merr.New(merr.Forbidden, "You do not have permission to perform this action."))
	default:
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
	}
}

func (s *Service) principalOr401(c *gin.Context) (string, string, bool) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return "", "", false
	}
	return p.UserID, p.OrgID, true
}

// Cancel handles POST /meetings/:meeting_id/cancel (host, before live).
func (s *Service) Cancel(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if !authz.CanEditOrCancel(role) {
		WriteError(c, merr.New(merr.Forbidden, "Only the host may cancel the meeting.").WithDetail("required_role", "H"))
		return
	}
	m, err := s.Store.Transition(c.Request.Context(), meetingID, meeting.StatusCancelled, "", ifMatch(c))
	if err != nil {
		mapControlError(c, err)
		return
	}
	WriteJSON(c, http.StatusOK, summaryOf(m))
}

// End handles POST /meetings/:meeting_id/end (host only).
func (s *Service) End(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if !authz.CanEnd(role) {
		WriteError(c, merr.New(merr.Forbidden, "Only the host may end the meeting.").WithDetail("required_role", "H"))
		return
	}
	m, err := s.Store.Transition(c.Request.Context(), meetingID, meeting.StatusEnded, "host_end", ifMatch(c))
	if err != nil {
		mapControlError(c, err)
		return
	}
	WriteJSON(c, http.StatusOK, summaryOf(m))
}

// Lock handles PUT /meetings/:meeting_id/lock (host/cohost).
func (s *Service) Lock(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	var req struct {
		Locked bool `json:"locked"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.Forbidden, "Invalid lock request."))
		return
	}
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if !authz.CanLock(role) {
		WriteError(c, merr.New(merr.Forbidden, "You may not lock this meeting.").WithDetail("required_role", "H"))
		return
	}
	m, err := s.Store.SetLock(c.Request.Context(), meetingID, req.Locked, ifMatch(c))
	if err != nil {
		mapControlError(c, err)
		return
	}
	WriteJSON(c, http.StatusOK, summaryOf(m))
}

// SetParticipantRole handles PUT /meetings/:meeting_id/participants/:uid/role (host only).
func (s *Service) SetParticipantRole(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	target := c.Param("uid")
	var req struct {
		Role string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Role != "C" && req.Role != "M") {
		WriteError(c, merr.New(merr.Forbidden, "Invalid role."))
		return
	}
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if !authz.CanSetRole(role) {
		WriteError(c, merr.New(merr.Forbidden, "Only the host may assign roles.").WithDetail("required_role", "H"))
		return
	}
	m, err := s.Store.SetRole(c.Request.Context(), meetingID, target, req.Role, ifMatch(c))
	if err != nil {
		mapControlError(c, err)
		return
	}
	WriteJSON(c, http.StatusOK, summaryOf(m))
}

// RemoveParticipant handles DELETE /meetings/:meeting_id/participants/:uid (host/cohost).
func (s *Service) RemoveParticipant(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	target := c.Param("uid")
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	targetRoleStr, _, err := s.Store.ParticipantRole(c.Request.Context(), meetingID, target)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	targetRole := authz.Role(targetRoleStr)
	if targetRole == "" {
		targetRole = authz.Member
	}
	if !authz.CanRemove(role, targetRole) {
		WriteError(c, merr.New(merr.Forbidden, "You may not remove this participant."))
		return
	}
	if err := s.Store.Remove(c.Request.Context(), meetingID, target); err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	WriteJSON(c, http.StatusOK, gin.H{"ok": true})
}

// Mute handles POST /meetings/:meeting_id/controls/mute (host/cohost).
func (s *Service) Mute(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	var req struct {
		TargetUID string `json:"target_uid"`
		All       bool   `json:"all"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.Forbidden, "Invalid mute request."))
		return
	}
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	if req.All {
		if !authz.CanMuteAll(role) {
			WriteError(c, merr.New(merr.Forbidden, "You may not mute all participants.").WithDetail("required_role", "H"))
			return
		}
		WriteJSON(c, http.StatusOK, gin.H{"ok": true, "scope": "all"})
		return
	}
	targetRoleStr, _, err := s.Store.ParticipantRole(c.Request.Context(), meetingID, req.TargetUID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	targetRole := authz.Role(targetRoleStr)
	if targetRole == "" {
		targetRole = authz.Member
	}
	if !authz.CanMute(role, targetRole) {
		WriteError(c, merr.New(merr.Forbidden, "You may not mute this participant."))
		return
	}
	WriteJSON(c, http.StatusOK, gin.H{"ok": true})
}

// StartShare handles POST /meetings/:meeting_id/share (single holder).
func (s *Service) StartShare(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	var req struct {
		ParticipantSegmentID string `json:"participant_segment_id"`
		ShareType            string `json:"share_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		WriteError(c, merr.New(merr.Forbidden, "Invalid share request."))
		return
	}
	if _, ok := s.actorRole(c, meetingID, uid); !ok {
		return
	}
	holder, acquired, err := s.Store.AcquireShare(c.Request.Context(), meetingID, uid, req.ParticipantSegmentID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if !acquired {
		WriteError(c, merr.New(merr.ShareConflict, "Another participant is already sharing.").WithDetail("holder_uid", holder))
		return
	}
	WriteJSON(c, http.StatusOK, gin.H{"holder_uid": uid, "active": true})
}

// StopShare handles DELETE /meetings/:meeting_id/share.
func (s *Service) StopShare(c *gin.Context) {
	uid, _, ok := s.principalOr401(c)
	if !ok {
		return
	}
	meetingID := c.Param("meeting_id")
	role, ok := s.actorRole(c, meetingID, uid)
	if !ok {
		return
	}
	holderUID, err := s.Store.ShareHolder(c.Request.Context(), meetingID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if holderUID == "" {
		WriteJSON(c, http.StatusOK, gin.H{"active": false}) // idempotent: nothing to stop
		return
	}
	holderRoleStr, _, err := s.Store.ParticipantRole(c.Request.Context(), meetingID, holderUID)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	holderRole := authz.Role(holderRoleStr)
	if holderRole == "" {
		holderRole = authz.Member
	}
	if !authz.CanStopShare(role, holderRole, holderUID == uid) {
		WriteError(c, merr.New(merr.Forbidden, "You may not stop this share."))
		return
	}
	if err := s.Store.ReleaseShare(c.Request.Context(), meetingID); err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	WriteJSON(c, http.StatusOK, gin.H{"active": false})
}
