package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/credential"
	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// readHarness wires the read endpoints into a gin engine with request-id +
// fail-closed identity, exactly as the server mounts them, over an in-memory
// read store and a real credential minter (so display-safe number/link decrypt
// is exercised).
type readHarness struct {
	engine *gin.Engine
	read   *repo.MemReadStore
	minter *credential.Minter
}

func newReadHarness(t *testing.T) *readHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	read := repo.NewMemReadStore()
	m, err := credential.NewMinter([]byte("read-test-lookup"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	svc := &Service{
		Store:       repo.NewMemStore(),
		ReadStore:   read,
		Space:       &fakeSpace{members: map[string]bool{}},
		Cfg:         DefaultConfig(),
		Credentials: m,
	}
	auth := fakeAuth{byToken: map[string]*seams.Principal{
		"tok-alice": {UserID: "alice", OrgID: "space-1"}, // creator/host in tests
		"tok-bob":   {UserID: "bob", OrgID: "space-1"},   // invitee/participant in tests
		"tok-dave":  {UserID: "dave", OrgID: "space-1"},  // same Space, unrelated
		"tok-eve":   {UserID: "eve", OrgID: "space-2"},   // cross-Space
	}}
	e := gin.New()
	v1 := e.Group("/v1")
	v1.Use(RequestID(), Identity(auth))
	svc.Register(v1)
	return &readHarness{engine: e, read: read, minter: m}
}

func (h *readHarness) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("token", token)
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

// seed registers a meeting under a space with sealed credential ciphertexts.
func (h *readHarness) seed(space string, sum repo.MeetingSummary, creator, host string, mutate func(*repo.MeetingDetail)) {
	num, _ := credential.GenerateNumber()
	link, _ := credential.GenerateLinkToken()
	nc, _ := h.minter.Seal(num)
	lc, _ := h.minter.Seal(link)
	sum.JoinLinkAvailable = true
	d := repo.MeetingDetail{
		Summary:      sum,
		SpaceID:      space,
		CreatorUID:   creator,
		HostUID:      host,
		NumberCipher: nc,
		LinkCipher:   lc,
	}
	if mutate != nil {
		mutate(&d)
	}
	h.read.AddMeeting(space, d)
}

type listBody struct {
	Items []struct {
		MeetingID         string `json:"meeting_id"`
		Status            string `json:"status"`
		Topic             string `json:"topic"`
		JoinLinkAvailable bool   `json:"join_link_available"`
	} `json:"items"`
	NextPageToken string `json:"next_page_token"`
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listBody {
	t.Helper()
	var b listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode list: %v (body=%s)", err, rec.Body.String())
	}
	return b
}

func TestListEmptyReturns200EmptyItems(t *testing.T) {
	h := newReadHarness(t)
	rec := h.get(t, "/v1/meetings?view=upcoming", "tok-alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("empty list: got %d, want 200", rec.Code)
	}
	// items must serialize as a present, empty array, never null and never a 404.
	if got := rec.Body.String(); got != `{"items":[]}` {
		t.Fatalf("empty list body = %s, want {\"items\":[]}", got)
	}
}

func TestListVisibilityViewsAndScoping(t *testing.T) {
	h := newReadHarness(t)
	base := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	// Alice's own meetings, one per view.
	h.seed("space-1", repo.MeetingSummary{MeetingID: "m-up", Type: meeting.TypeScheduled, Status: meeting.StatusScheduled, Topic: "Sync", ScheduledStartAt: base, Version: 1}, "alice", "alice", nil)
	h.seed("space-1", repo.MeetingSummary{MeetingID: "m-hist", Type: meeting.TypeScheduled, Status: meeting.StatusEnded, EndedAt: base, Version: 3}, "alice", "alice", nil)
	// Same Space, but alice is unrelated -> must not appear.
	h.seed("space-1", repo.MeetingSummary{MeetingID: "m-other", Status: meeting.StatusLive, ActualStartAt: base, Version: 1}, "dave", "dave", nil)
	// Alice is creator but the meeting lives in another Space -> scoped out.
	h.seed("space-2", repo.MeetingSummary{MeetingID: "m-xspace", Status: meeting.StatusScheduled, ScheduledStartAt: base, Version: 1}, "alice", "alice", nil)

	up := decodeList(t, h.get(t, "/v1/meetings?view=upcoming", "tok-alice"))
	if len(up.Items) != 1 || up.Items[0].MeetingID != "m-up" {
		t.Fatalf("upcoming = %+v, want only m-up", up.Items)
	}
	hist := decodeList(t, h.get(t, "/v1/meetings?view=history", "tok-alice"))
	if len(hist.Items) != 1 || hist.Items[0].MeetingID != "m-hist" {
		t.Fatalf("history = %+v, want only m-hist", hist.Items)
	}
}

func TestListRelationshipVisibility(t *testing.T) {
	h := newReadHarness(t)
	base := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	// Bob is an invitee on one meeting and a participant on another; both created
	// by alice, so bob is neither creator nor host.
	h.seed("space-1", repo.MeetingSummary{MeetingID: "m-inv", Status: meeting.StatusScheduled, ScheduledStartAt: base, Version: 1}, "alice", "alice", func(d *repo.MeetingDetail) {
		d.Invites = []repo.MeetingInvite{{InviteeUID: "bob", Status: "invited", InvitedBy: "alice", Version: 1}}
	})
	h.seed("space-1", repo.MeetingSummary{MeetingID: "m-part", Status: meeting.StatusLive, ActualStartAt: base.Add(time.Minute), Version: 1}, "alice", "alice", func(d *repo.MeetingDetail) {
		d.Participants = []repo.MeetingParticipant{{UID: "bob", Role: "M", AggregateState: "joined", Version: 1}}
	})

	got := decodeList(t, h.get(t, "/v1/meetings?view=upcoming", "tok-bob"))
	if len(got.Items) != 2 {
		t.Fatalf("bob upcoming = %+v, want 2 (invitee + participant)", got.Items)
	}
	// Dave (same Space, unrelated) sees neither.
	none := decodeList(t, h.get(t, "/v1/meetings?view=upcoming", "tok-dave"))
	if len(none.Items) != 0 {
		t.Fatalf("dave upcoming = %+v, want 0", none.Items)
	}
}

func TestListUnknownViewAndBadToken(t *testing.T) {
	h := newReadHarness(t)
	if rec := h.get(t, "/v1/meetings?view=ongoing", "tok-alice"); rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("unknown view: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}
	if rec := h.get(t, "/v1/meetings", "tok-alice"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing view: got %d, want 404", rec.Code)
	}
	if rec := h.get(t, "/v1/meetings?view=upcoming&page_token=not-a-cursor", "tok-alice"); rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("bad token: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}
}

func TestListPaginationKeyset(t *testing.T) {
	h := newReadHarness(t)
	base := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"p1", "p2", "p3"} {
		h.seed("space-1", repo.MeetingSummary{MeetingID: id, Status: meeting.StatusScheduled, ScheduledStartAt: base.Add(time.Duration(i) * time.Hour), Version: 1}, "alice", "alice", nil)
	}
	first := decodeList(t, h.get(t, "/v1/meetings?view=upcoming&page_size=2", "tok-alice"))
	if len(first.Items) != 2 || first.Items[0].MeetingID != "p1" || first.Items[1].MeetingID != "p2" {
		t.Fatalf("page 1 = %+v, want [p1 p2]", first.Items)
	}
	if first.NextPageToken == "" {
		t.Fatal("page 1: expected next_page_token")
	}
	second := decodeList(t, h.get(t, "/v1/meetings?view=upcoming&page_size=2&page_token="+first.NextPageToken, "tok-alice"))
	if len(second.Items) != 1 || second.Items[0].MeetingID != "p3" {
		t.Fatalf("page 2 = %+v, want [p3]", second.Items)
	}
	if second.NextPageToken != "" {
		t.Fatalf("page 2: unexpected next_page_token %q", second.NextPageToken)
	}
}

func TestDetailAuthorizedCreator(t *testing.T) {
	h := newReadHarness(t)
	start := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	h.seed("space-1", repo.MeetingSummary{
		MeetingID: "d1", Type: meeting.TypeScheduled, Status: meeting.StatusEnded,
		Topic: "Retro", ScheduledStartAt: start, ActualStartAt: start.Add(2 * time.Minute),
		EndedAt: start.Add(30 * time.Minute), EndReason: "host_end", PasswordEnabled: true, Version: 8,
	}, "alice", "alice", func(d *repo.MeetingDetail) {
		d.Participants = []repo.MeetingParticipant{{
			UID: "bob", Role: "M", AggregateState: "left",
			FirstJoinedAt: start.Add(3 * time.Minute), LastLeftAt: start.Add(29 * time.Minute), Version: 2,
			Segments: []repo.MeetingSegment{
				{SegmentID: "seg-1", JoinAt: start.Add(3 * time.Minute), LeaveAt: start.Add(12 * time.Minute), EndReason: "superseded", SupersededBySegmentID: "seg-2"},
				{SegmentID: "seg-2", JoinAt: start.Add(14 * time.Minute), LeaveAt: start.Add(29 * time.Minute), EndReason: "left"},
			},
		}}
		d.Invites = []repo.MeetingInvite{{InviteeUID: "carol", Status: "invited", InvitedBy: "alice", Version: 1}}
	})

	rec := h.get(t, "/v1/meetings/d1", "tok-alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("creator detail: got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		MeetingID     string `json:"meeting_id"`
		Topic         string `json:"topic"`
		EndReason     string `json:"end_reason"`
		CreatorUID    string `json:"creator_uid"`
		MeetingNumber string `json:"meeting_number"`
		JoinLink      string `json:"join_link"`
		Participants  []struct {
			UID           string `json:"uid"`
			FirstJoinedAt string `json:"first_joined_at"`
			LastLeftAt    string `json:"last_left_at"`
			Segments      []struct {
				SegmentID             string `json:"segment_id"`
				JoinAt                string `json:"join_at"`
				LeaveAt               string `json:"leave_at"`
				EndReason             string `json:"end_reason"`
				SupersededBySegmentID string `json:"superseded_by_segment_id"`
			} `json:"segments"`
		} `json:"participants"`
		Invites []struct {
			InviteeUID string `json:"invitee_uid"`
		} `json:"invites"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if body.CreatorUID != "alice" || body.Topic != "Retro" || body.EndReason != "host_end" {
		t.Fatalf("detail core fields wrong: %+v", body)
	}
	if body.MeetingNumber == "" || body.JoinLink == "" {
		t.Fatalf("creator must see decrypted number/link, got number=%q link=%q", body.MeetingNumber, body.JoinLink)
	}
	if len(body.Participants) != 1 || body.Participants[0].UID != "bob" || body.Participants[0].LastLeftAt == "" {
		t.Fatalf("participants wrong: %+v", body.Participants)
	}
	// Multi-segment timeline: ordered by join_at, superseded segment first with a
	// forward pointer, then the terminal "left" segment (MTG-FR-081).
	segs := body.Participants[0].Segments
	if len(segs) != 2 {
		t.Fatalf("want 2 segments, got %+v", segs)
	}
	if segs[0].SegmentID != "seg-1" || segs[0].EndReason != "superseded" || segs[0].SupersededBySegmentID != "seg-2" || segs[0].LeaveAt == "" {
		t.Fatalf("segment 0 wrong: %+v", segs[0])
	}
	if segs[1].SegmentID != "seg-2" || segs[1].EndReason != "left" || segs[1].SupersededBySegmentID != "" || segs[1].JoinAt == "" {
		t.Fatalf("segment 1 wrong: %+v", segs[1])
	}
	if len(body.Invites) != 1 || body.Invites[0].InviteeUID != "carol" {
		t.Fatalf("invites wrong: %+v", body.Invites)
	}
}

func TestDetailParticipantHidesCredentials(t *testing.T) {
	h := newReadHarness(t)
	h.seed("space-1", repo.MeetingSummary{MeetingID: "d2", Status: meeting.StatusLive, PasswordEnabled: false, Version: 1}, "alice", "alice", func(d *repo.MeetingDetail) {
		d.Participants = []repo.MeetingParticipant{{UID: "bob", Role: "M", AggregateState: "joined", Version: 1}}
	})
	rec := h.get(t, "/v1/meetings/d2", "tok-bob")
	if rec.Code != http.StatusOK {
		t.Fatalf("participant detail: got %d", rec.Code)
	}
	var body struct {
		MeetingNumber     string `json:"meeting_number"`
		JoinLink          string `json:"join_link"`
		JoinLinkAvailable bool   `json:"join_link_available"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.MeetingNumber != "" || body.JoinLink != "" {
		t.Fatalf("participant must not see raw number/link, got number=%q link=%q", body.MeetingNumber, body.JoinLink)
	}
	if !body.JoinLinkAvailable {
		t.Fatal("participant should still see join_link_available=true")
	}
}

func TestDetailUnauthorizedIsIndistinguishable404(t *testing.T) {
	h := newReadHarness(t)
	h.seed("space-1", repo.MeetingSummary{MeetingID: "d3", Status: meeting.StatusScheduled, Version: 1}, "alice", "alice", nil)

	// Same-Space but unrelated caller.
	if rec := h.get(t, "/v1/meetings/d3", "tok-dave"); rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("unrelated detail: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}
	// Cross-Space caller.
	if rec := h.get(t, "/v1/meetings/d3", "tok-eve"); rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("cross-space detail: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}
	// Unknown meeting: same indistinguishable 404.
	if rec := h.get(t, "/v1/meetings/nope", "tok-alice"); rec.Code != http.StatusNotFound || decodeCode(t, rec) != "MEETING_CREDENTIAL_INVALID" {
		t.Fatalf("unknown detail: got %d %s, want 404 MEETING_CREDENTIAL_INVALID", rec.Code, decodeCode(t, rec))
	}
}
