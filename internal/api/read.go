package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// meetingSummaryDTO is the wire shape of a list row (openapi meeting_summary).
// Optional fields are omitted when absent (no `null` for unset date-times), and
// no raw password or link token is ever present — only join_link_available.
type meetingSummaryDTO struct {
	MeetingID         string  `json:"meeting_id"`
	Type              string  `json:"type"`
	Status            string  `json:"status"`
	Topic             string  `json:"topic,omitempty"`
	ScheduledStartAt  *string `json:"scheduled_start_at,omitempty"`
	DurationMinutes   *int    `json:"duration_minutes,omitempty"`
	ActualStartAt     *string `json:"actual_start_at,omitempty"`
	EndedAt           *string `json:"ended_at,omitempty"`
	CancelledAt       *string `json:"cancelled_at,omitempty"`
	EndReason         string  `json:"end_reason,omitempty"`
	Locked            bool    `json:"locked"`
	PasswordEnabled   bool    `json:"password_enabled"`
	JoinLinkAvailable bool    `json:"join_link_available"`
	Version           int64   `json:"version"`
}

// meetingListResponseDTO is the list envelope (openapi meeting_list_response).
// Items is always a (possibly empty) array so an empty page renders as
// {"items": []}, never null and never a 404.
type meetingListResponseDTO struct {
	Items         []meetingSummaryDTO `json:"items"`
	NextPageToken string              `json:"next_page_token,omitempty"`
}

// participantDTO is the identity-aggregated participant row (openapi participant).
type participantDTO struct {
	UID            string  `json:"uid"`
	Role           string  `json:"role"`
	AggregateState string  `json:"aggregate_state"`
	Removed        bool    `json:"removed"`
	FirstJoinedAt  *string `json:"first_joined_at,omitempty"`
	LastLeftAt     *string `json:"last_left_at,omitempty"`
	Version        int64   `json:"version"`
}

// inviteDTO is an invite row (openapi invite).
type inviteDTO struct {
	InviteeUID string `json:"invitee_uid"`
	Status     string `json:"status"`
	InvitedBy  string `json:"invited_by,omitempty"`
	Version    int64  `json:"version"`
}

// meetingDetailDTO is the detail object (openapi meeting_detail = meeting_summary
// plus identity/credential/participant/invite fields). meeting_number and
// join_link are populated only for a credential-authorized viewer.
type meetingDetailDTO struct {
	meetingSummaryDTO
	CreatorUID    string           `json:"creator_uid,omitempty"`
	HostUID       string           `json:"host_uid,omitempty"`
	MeetingNumber string           `json:"meeting_number,omitempty"`
	JoinLink      string           `json:"join_link,omitempty"`
	Participants  []participantDTO `json:"participants"`
	Invites       []inviteDTO      `json:"invites"`
}

// ListMeetings handles GET /meetings. It returns the caller-visible page of
// summaries for the requested view. It reuses the same fail-closed identity as
// the write/control routes (no token -> 401 upstream), constrains visibility to
// the trusted principal's Space + relationship, and never returns a 404 for an
// empty result.
func (s *Service) ListMeetings(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	view, ok := repo.ParseListView(c.Query("view"))
	if !ok {
		// `view` is a required enum [upcoming, history]; an unknown value (e.g. the
		// withdrawn `ongoing`) is rejected via the canonical envelope rather than
		// silently aliased. The frozen error taxonomy has no dedicated query-
		// validation code, so the resource-style credential-invalid 404 is reused.
		WriteError(c, merr.New(merr.CredentialInvalid, "The requested meeting view is invalid."))
		return
	}
	page := repo.Page{Size: parsePageSize(c.Query("page_size")), Token: c.Query("page_token")}
	if page.Token != "" {
		if _, _, ok := repo.DecodeCursor(page.Token, view); !ok {
			WriteError(c, merr.New(merr.CredentialInvalid, "The page token is invalid."))
			return
		}
	}
	res, err := s.ReadStore.ListVisibleMeetings(c.Request.Context(), p.OrgID, p.UserID, view, page)
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	out := meetingListResponseDTO{Items: make([]meetingSummaryDTO, 0, len(res.Items))}
	for _, it := range res.Items {
		out.Items = append(out.Items, toSummaryDTO(it))
	}
	out.NextPageToken = res.NextPageToken
	WriteJSON(c, http.StatusOK, out)
}

// GetMeeting handles GET /meetings/:meeting_id (read-only detail; the existing
// PATCH on the same path is the unchanged write handler). A non-existent,
// cross-Space, or unrelated meeting all collapse to the same indistinguishable
// 404, so neither existence nor credentials leak (S-1, mirroring admission).
func (s *Service) GetMeeting(c *gin.Context) {
	p, ok := PrincipalOf(c)
	if !ok {
		WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
		return
	}
	d, found, err := s.ReadStore.GetMeetingDetail(c.Request.Context(), c.Param("meeting_id"))
	if err != nil {
		WriteError(c, merr.New(merr.Internal, "An unexpected error occurred."))
		return
	}
	if !found || d.SpaceID != p.OrgID || !detailVisible(d, p.UserID) {
		WriteError(c, merr.New(merr.CredentialInvalid, "The meeting number or link is invalid."))
		return
	}
	WriteJSON(c, http.StatusOK, s.toDetailDTO(d, p.UserID))
}

// detailVisible reports whether the caller may see a meeting's detail: creator,
// host, an invited member, or a participant. It is the read-side counterpart of
// the admission S-1 authorization-to-know envelope.
func detailVisible(d repo.MeetingDetail, uid string) bool {
	if d.CreatorUID == uid || d.HostUID == uid {
		return true
	}
	for _, iv := range d.Invites {
		if iv.InviteeUID == uid && iv.Status == "invited" {
			return true
		}
	}
	for _, pt := range d.Participants {
		if pt.UID == uid {
			return true
		}
	}
	return false
}

// credentialDisplayAllowed reports whether the caller may see the display-safe
// meeting number and join link: the creator, host, or an invited member (openapi
// meeting_detail join_link note). A plain participant sees join_link_available
// but not the raw values.
func credentialDisplayAllowed(d repo.MeetingDetail, uid string) bool {
	if d.CreatorUID == uid || d.HostUID == uid {
		return true
	}
	for _, iv := range d.Invites {
		if iv.InviteeUID == uid && iv.Status == "invited" {
			return true
		}
	}
	return false
}

func (s *Service) toDetailDTO(d repo.MeetingDetail, uid string) meetingDetailDTO {
	out := meetingDetailDTO{
		meetingSummaryDTO: toSummaryDTO(d.Summary),
		CreatorUID:        d.CreatorUID,
		HostUID:           d.HostUID,
		Participants:      make([]participantDTO, 0, len(d.Participants)),
		Invites:           make([]inviteDTO, 0, len(d.Invites)),
	}
	if s.Credentials != nil && credentialDisplayAllowed(d, uid) {
		if len(d.NumberCipher) > 0 {
			if n, err := s.Credentials.Open(d.NumberCipher); err == nil {
				out.MeetingNumber = n
			}
		}
		if len(d.LinkCipher) > 0 {
			if l, err := s.Credentials.Open(d.LinkCipher); err == nil {
				out.JoinLink = l
			}
		}
	}
	for _, pt := range d.Participants {
		out.Participants = append(out.Participants, participantDTO{
			UID:            pt.UID,
			Role:           pt.Role,
			AggregateState: pt.AggregateState,
			Removed:        pt.Removed,
			FirstJoinedAt:  isoPtr(pt.FirstJoinedAt),
			LastLeftAt:     isoPtr(pt.LastLeftAt),
			Version:        pt.Version,
		})
	}
	for _, iv := range d.Invites {
		out.Invites = append(out.Invites, inviteDTO{
			InviteeUID: iv.InviteeUID,
			Status:     iv.Status,
			InvitedBy:  iv.InvitedBy,
			Version:    iv.Version,
		})
	}
	return out
}

func toSummaryDTO(m repo.MeetingSummary) meetingSummaryDTO {
	dto := meetingSummaryDTO{
		MeetingID:         m.MeetingID,
		Type:              string(m.Type),
		Status:            string(m.Status),
		Topic:             m.Topic,
		ScheduledStartAt:  isoPtr(m.ScheduledStartAt),
		ActualStartAt:     isoPtr(m.ActualStartAt),
		EndedAt:           isoPtr(m.EndedAt),
		CancelledAt:       isoPtr(m.CancelledAt),
		EndReason:         m.EndReason,
		Locked:            m.Locked,
		PasswordEnabled:   m.PasswordEnabled,
		JoinLinkAvailable: m.JoinLinkAvailable,
		Version:           m.Version,
	}
	if m.DurationMinutes > 0 {
		d := m.DurationMinutes
		dto.DurationMinutes = &d
	}
	return dto
}

// isoPtr renders a UTC RFC3339 timestamp, or nil for the zero value so an absent
// time is omitted from the wire object rather than serialized as null.
func isoPtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// parsePageSize reads a lenient page_size query value; a missing or unparseable
// value falls back to the approved default, and bounds are clamped downstream.
func parsePageSize(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}
