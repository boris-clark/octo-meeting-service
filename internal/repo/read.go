package repo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
)

// MeetingListView selects which meetings a list query returns. The approved MVP
// v0.3 read contract defines exactly two views; live meetings fold into
// upcoming, and there is intentionally no `ongoing` view.
type MeetingListView string

// The only list views in the approved contract (openapi meeting list `view`
// enum: [upcoming, history]).
const (
	ViewUpcoming MeetingListView = "upcoming"
	ViewHistory  MeetingListView = "history"
)

// ParseListView validates the wire `view` parameter against the frozen enum. It
// deliberately does not treat `ongoing` (or any other value) as an alias.
func ParseListView(s string) (MeetingListView, bool) {
	switch MeetingListView(s) {
	case ViewUpcoming:
		return ViewUpcoming, true
	case ViewHistory:
		return ViewHistory, true
	default:
		return "", false
	}
}

// Pagination bounds from the approved list contract (openapi page_size:
// minimum 1, maximum 100, default 20).
const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// Page carries the validated pagination inputs for a list query. Token is the
// opaque forward cursor ("" for the first page).
type Page struct {
	Size  int
	Token string
}

// ClampPageSize applies the approved default/max bounds to a requested size.
func ClampPageSize(n int) int {
	if n <= 0 {
		return DefaultPageSize
	}
	if n > MaxPageSize {
		return MaxPageSize
	}
	return n
}

// MeetingSummary is the approved v0.3 list row (openapi meeting_summary). Zero
// time values and a zero DurationMinutes mean "absent" and are omitted at the
// wire layer. It never carries a raw password or link token — only the
// join_link_available flag.
type MeetingSummary struct {
	MeetingID         string
	Type              meeting.Type
	Status            meeting.Status
	Topic             string
	ScheduledStartAt  time.Time
	DurationMinutes   int
	ActualStartAt     time.Time
	EndedAt           time.Time
	CancelledAt       time.Time
	EndReason         string
	Locked            bool
	PasswordEnabled   bool
	JoinLinkAvailable bool
	Version           int64
}

// MeetingListPage is one page of summaries plus the opaque forward cursor. An
// empty Items slice with an empty NextPageToken is the empty-state result.
type MeetingListPage struct {
	Items         []MeetingSummary
	NextPageToken string
}

// MeetingParticipant is the identity-aggregated participant row (openapi
// participant): one entry per uid with the first-join/last-leave envelope across
// all of that uid's segments, plus the ordered per-segment timeline (MTG-FR-081
// multi-segment history) in Segments.
type MeetingParticipant struct {
	UID            string
	Role           string
	AggregateState string
	Removed        bool
	FirstJoinedAt  time.Time
	LastLeftAt     time.Time
	Version        int64
	Segments       []MeetingSegment
}

// MeetingSegment is one join/leave interval of a participant (openapi
// participant_segment, display subset). It exposes only the timeline fields —
// never device_id_hash, livekit_identity, or any credential material.
type MeetingSegment struct {
	SegmentID             string
	JoinAt                time.Time
	LeaveAt               time.Time
	EndReason             string
	SupersededBySegmentID string
}

// MeetingInvite is an invite row (openapi invite).
type MeetingInvite struct {
	InviteeUID string
	Status     string
	InvitedBy  string
	Version    int64
}

// MeetingDetail is the approved v0.3 detail projection (openapi meeting_detail =
// meeting_summary + identity/credential/participant/invite fields). NumberCipher
// and LinkCipher are the at-rest display ciphertexts; the read store never
// decrypts them — the handler opens them only for an authorized viewer, so an
// unauthorized detail response leaks no credential material.
type MeetingDetail struct {
	Summary      MeetingSummary
	SpaceID      string
	CreatorUID   string
	HostUID      string
	NumberCipher []byte
	LinkCipher   []byte
	Participants []MeetingParticipant
	Invites      []MeetingInvite
}

// MeetingReadStore is the read-only projection seam for the list/detail
// endpoints. It is kept separate from the admission/control Store so the write
// path's deliberately minimal projection is not disturbed (repo.Meeting omits
// topic, terminal times, participants, and invites). Visibility is constrained
// in the query by the trusted principal (space + relationship); browser identity
// headers are never consulted.
type MeetingReadStore interface {
	// ListVisibleMeetings returns the caller-visible meetings for the view,
	// forward-paginated by the opaque token in page. An empty result is not an
	// error.
	ListVisibleMeetings(ctx context.Context, spaceID, uid string, view MeetingListView, page Page) (MeetingListPage, error)
	// GetMeetingDetail returns the meeting projection regardless of the caller;
	// authorization is applied by the handler so a non-existent, cross-Space, and
	// unrelated meeting are indistinguishable. found=false means no such row.
	GetMeetingDetail(ctx context.Context, meetingID string) (MeetingDetail, bool, error)
}

// listCursor is the opaque keyset cursor. It pins the view so a token minted for
// one view cannot be replayed against another, and carries the last row's sort
// timestamp (unix millis, UTC) plus the internal row id tie-breaker.
type listCursor struct {
	View string `json:"v"`
	TS   int64  `json:"ts"`
	ID   int64  `json:"id"`
}

// EncodeCursor renders an opaque forward cursor for the given view/sort-key/id.
func EncodeCursor(view MeetingListView, ts time.Time, id int64) string {
	b, _ := json.Marshal(listCursor{View: string(view), TS: ts.UTC().UnixMilli(), ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses a forward cursor and verifies it was minted for view. ok
// is false for a malformed token or a view mismatch.
func DecodeCursor(token string, view MeetingListView) (ts time.Time, id int64, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, 0, false
	}
	var c listCursor
	if err := json.Unmarshal(raw, &c); err != nil || c.View != string(view) {
		return time.Time{}, 0, false
	}
	return time.UnixMilli(c.TS).UTC(), c.ID, true
}

// MemReadStore is an in-memory MeetingReadStore for unit/handler tests. It mirrors
// the MySQL store's visibility and ordering semantics closely enough to exercise
// the handlers deterministically.
type MemReadStore struct {
	mu   sync.Mutex
	seq  int64
	recs map[string]*memReadRecord
}

type memReadRecord struct {
	id     int64
	space  string
	detail MeetingDetail
}

// NewMemReadStore builds an empty in-memory read store.
func NewMemReadStore() *MemReadStore {
	return &MemReadStore{recs: map[string]*memReadRecord{}}
}

// AddMeeting registers a meeting (with its detail projection) under a space. The
// caller's relationship for visibility/authorization is derived from the
// detail's creator/host and its Participants/Invites, exactly as the handler
// does over the MySQL store.
func (m *MemReadStore) AddMeeting(space string, d MeetingDetail) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.recs[d.Summary.MeetingID] = &memReadRecord{id: m.seq, space: space, detail: d}
}

func (m *MemReadStore) related(d MeetingDetail, uid string) bool {
	if d.CreatorUID == uid || d.HostUID == uid {
		return true
	}
	for _, iv := range d.Invites {
		if iv.InviteeUID == uid && iv.Status == "invited" {
			return true
		}
	}
	for _, p := range d.Participants {
		if p.UID == uid {
			return true
		}
	}
	return false
}

func inView(view MeetingListView, s meeting.Status) bool {
	switch view {
	case ViewUpcoming:
		return s == meeting.StatusScheduled || s == meeting.StatusLive
	case ViewHistory:
		return s == meeting.StatusEnded || s == meeting.StatusCancelled
	default:
		return false
	}
}

// sortKey returns the per-view ordering timestamp for a record, matching the
// MySQL COALESCE expressions.
func sortKey(view MeetingListView, r *memReadRecord) time.Time {
	sum := r.detail.Summary
	pick := func(ts ...time.Time) time.Time {
		for _, t := range ts {
			if !t.IsZero() {
				return t
			}
		}
		return time.UnixMilli(r.id) // stable non-zero fallback for tests
	}
	if view == ViewUpcoming {
		return pick(sum.ScheduledStartAt, sum.ActualStartAt)
	}
	return pick(sum.EndedAt, sum.CancelledAt, sum.ScheduledStartAt)
}

// ListVisibleMeetings implements MeetingReadStore.
func (m *MemReadStore) ListVisibleMeetings(_ context.Context, spaceID, uid string, view MeetingListView, page Page) (MeetingListPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	type row struct {
		rec *memReadRecord
		key time.Time
	}
	var rows []row
	for _, r := range m.recs {
		if r.space != spaceID || !inView(view, r.detail.Summary.Status) || !m.related(r.detail, uid) {
			continue
		}
		rows = append(rows, row{rec: r, key: sortKey(view, r)})
	}

	asc := view == ViewUpcoming
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].key.Equal(rows[j].key) {
			if asc {
				return rows[i].rec.id < rows[j].rec.id
			}
			return rows[i].rec.id > rows[j].rec.id
		}
		if asc {
			return rows[i].key.Before(rows[j].key)
		}
		return rows[i].key.After(rows[j].key)
	})

	// Apply the keyset cursor: keep rows strictly after the cursor position.
	if page.Token != "" {
		if ts, id, ok := DecodeCursor(page.Token, view); ok {
			filtered := rows[:0:0]
			for _, r := range rows {
				after := false
				if asc {
					after = r.key.After(ts) || (r.key.Equal(ts) && r.rec.id > id)
				} else {
					after = r.key.Before(ts) || (r.key.Equal(ts) && r.rec.id < id)
				}
				if after {
					filtered = append(filtered, r)
				}
			}
			rows = filtered
		}
	}

	size := ClampPageSize(page.Size)
	out := MeetingListPage{Items: make([]MeetingSummary, 0, size)}
	for i, r := range rows {
		if i >= size {
			out.NextPageToken = EncodeCursor(view, rows[i-1].key, rows[i-1].rec.id)
			break
		}
		out.Items = append(out.Items, r.rec.detail.Summary)
	}
	return out, nil
}

// GetMeetingDetail implements MeetingReadStore.
func (m *MemReadStore) GetMeetingDetail(_ context.Context, meetingID string) (MeetingDetail, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[meetingID]
	if !ok {
		return MeetingDetail{}, false, nil
	}
	d := r.detail
	d.SpaceID = r.space
	return d, true, nil
}
