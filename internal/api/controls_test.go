package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
	"github.com/Jerry-Xin/octo-meeting-service/internal/repo"
)

// controlMeeting seeds a meeting with alice as host and bob as a participant of
// the given role, and marks both same-Space members.
func controlMeeting(h *harness, id string, status meeting.Status, bobRole string) {
	h.space.members["space-1|alice"] = true
	h.space.members["space-2|bob"] = true
	h.store.AddMeeting(repo.Meeting{
		MeetingID: id, SpaceID: "space-1", Type: meeting.TypeScheduled,
		Status: status, CreatorUID: "alice", HostUID: "alice", Version: 1,
	}, "", "")
	if bobRole != "" {
		h.store.SetRoleDirect(id, "bob", bobRole)
	}
}

func TestCancelAuthorizationAndVersion(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m1", meeting.StatusScheduled, "M")

	// A member cannot cancel.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m1/cancel", "tok-bob", map[string]any{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member cancel: got %d, want 403", rec.Code)
	}
	// Stale If-Match -> version conflict.
	rec := h.do(t, http.MethodPost, "/v1/meetings/m1/cancel", "tok-alice", map[string]any{}, map[string]string{"If-Match": "99"})
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_VERSION_CONFLICT" {
		t.Fatalf("stale version: got %d %s", rec.Code, decodeCode(t, rec))
	}
	// Host cancels -> cancelled.
	rec = h.do(t, http.MethodPost, "/v1/meetings/m1/cancel", "tok-alice", map[string]any{}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("host cancel: got %d body=%s", rec.Code, rec.Body.String())
	}
	m, _, _ := h.store.Resolve(nil, repo.ByID, "m1") //nolint:staticcheck // nil ctx ok for MemStore
	if m.Status != meeting.StatusCancelled {
		t.Fatalf("status = %v, want cancelled", m.Status)
	}
}

func TestEndHostOnly(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m2", meeting.StatusLive, "C")
	// Cohost cannot end.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m2/end", "tok-bob", map[string]any{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("cohost end: got %d, want 403", rec.Code)
	}
	// Host ends -> ended; repeat is idempotent.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m2/end", "tok-alice", map[string]any{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("host end: got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m2/end", "tok-alice", map[string]any{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("idempotent end: got %d", rec.Code)
	}
}

func TestLockHostOrCohost(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m3", meeting.StatusLive, "C")
	// Cohost may lock.
	if rec := h.do(t, http.MethodPut, "/v1/meetings/m3/lock", "tok-bob", map[string]any{"locked": true}, nil); rec.Code != http.StatusOK {
		t.Fatalf("cohost lock: got %d body=%s", rec.Code, rec.Body.String())
	}
	// A plain member may not.
	h.store.SetRoleDirect("m3", "bob", "M")
	if rec := h.do(t, http.MethodPut, "/v1/meetings/m3/lock", "tok-bob", map[string]any{"locked": false}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member lock: got %d, want 403", rec.Code)
	}
}

func TestSetRoleHostOnly(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m4", meeting.StatusLive, "M")
	// Host promotes bob to cohost.
	if rec := h.do(t, http.MethodPut, "/v1/meetings/m4/participants/bob/role", "tok-alice", map[string]any{"role": "C"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("host set role: got %d body=%s", rec.Code, rec.Body.String())
	}
	// Now-cohost bob cannot assign roles.
	if rec := h.do(t, http.MethodPut, "/v1/meetings/m4/participants/carol/role", "tok-bob", map[string]any{"role": "C"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("cohost set role: got %d, want 403", rec.Code)
	}
}

func TestRemoveBlocksAdmission(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m5", meeting.StatusLive, "M")
	// Host removes bob.
	if rec := h.do(t, http.MethodDelete, "/v1/meetings/m5/participants/bob", "tok-alice", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("host remove: got %d body=%s", rec.Code, rec.Body.String())
	}
	// A removed participant is authorized-to-know (existing participant) so gets a
	// concrete MEETING_REMOVED on evaluate, before any password step.
	rec := h.do(t, http.MethodPost, "/v1/meetings/admission/evaluate", "tok-bob",
		map[string]any{"source": "rejoin", "meeting_id": "m5"}, nil)
	if rec.Code != http.StatusForbidden || decodeCode(t, rec) != "MEETING_REMOVED" {
		t.Fatalf("removed evaluate: got %d %s, want 403 MEETING_REMOVED", rec.Code, decodeCode(t, rec))
	}
	// A member cannot remove others.
	if rec := h.do(t, http.MethodDelete, "/v1/meetings/m5/participants/carol", "tok-bob", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member remove: got %d, want 403", rec.Code)
	}
}

func TestMuteAuthorization(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m6", meeting.StatusLive, "M")
	// Host mutes a member.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m6/controls/mute", "tok-alice", map[string]any{"target_uid": "bob"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("host mute member: got %d", rec.Code)
	}
	// A member cannot mute.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m6/controls/mute", "tok-bob", map[string]any{"target_uid": "alice"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member mute: got %d, want 403", rec.Code)
	}
}

func TestShareConflict(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "m7", meeting.StatusLive, "M")

	// Host starts sharing.
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m7/share", "tok-alice",
		map[string]any{"participant_segment_id": "seg-a", "share_type": "screen"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("host start share: got %d body=%s", rec.Code, rec.Body.String())
	}
	// A second sharer conflicts, and the holder is disclosed.
	rec := h.do(t, http.MethodPost, "/v1/meetings/m7/share", "tok-bob",
		map[string]any{"participant_segment_id": "seg-b", "share_type": "screen"}, nil)
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_SHARE_CONFLICT" {
		t.Fatalf("share conflict: got %d %s", rec.Code, decodeCode(t, rec))
	}
	// The holder can stop; then a member may start.
	if rec := h.do(t, http.MethodDelete, "/v1/meetings/m7/share", "tok-alice", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("host stop share: got %d", rec.Code)
	}
	if rec := h.do(t, http.MethodPost, "/v1/meetings/m7/share", "tok-bob",
		map[string]any{"participant_segment_id": "seg-b", "share_type": "screen"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("member start after release: got %d", rec.Code)
	}
}

func TestRemoveStaleVersionConflict(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "mrv", meeting.StatusLive, "M")
	// Host remove with a stale If-Match -> version conflict (no removal applied).
	rec := h.do(t, http.MethodDelete, "/v1/meetings/mrv/participants/bob", "tok-alice", nil, map[string]string{"If-Match": "99"})
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_VERSION_CONFLICT" {
		t.Fatalf("stale remove: got %d %s, want 409 MEETING_VERSION_CONFLICT", rec.Code, decodeCode(t, rec))
	}
	// The correct version succeeds and blocks admission.
	if rec := h.do(t, http.MethodDelete, "/v1/meetings/mrv/participants/bob", "tok-alice", nil, map[string]string{"If-Match": "1"}); rec.Code != http.StatusOK {
		t.Fatalf("versioned remove: got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestShareStartStaleVersionConflict(t *testing.T) {
	h := newHarness(t, fakeMinter{token: "lk"}, time.Now())
	controlMeeting(h, "msv", meeting.StatusLive, "M")
	rec := h.do(t, http.MethodPost, "/v1/meetings/msv/share", "tok-alice",
		map[string]any{"participant_segment_id": "seg", "share_type": "screen"}, map[string]string{"If-Match": "99"})
	if rec.Code != http.StatusConflict || decodeCode(t, rec) != "MEETING_VERSION_CONFLICT" {
		t.Fatalf("stale share start: got %d %s, want 409 MEETING_VERSION_CONFLICT", rec.Code, decodeCode(t, rec))
	}
}
