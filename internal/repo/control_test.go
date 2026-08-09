package repo

import (
	"context"
	"testing"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/meeting"
)

func seedControl(id string) *MemStore {
	s := NewMemStore()
	s.AddMeeting(Meeting{MeetingID: id, SpaceID: "sp", Status: meeting.StatusLive, HostUID: "host", Version: 1}, "", "")
	return s
}

func TestMemRemoveVersionCheck(t *testing.T) {
	s := seedControl("m")
	ctx := context.Background()
	if _, err := s.Remove(ctx, "m", "bob", 99); err != ErrVersionConflict {
		t.Fatalf("stale remove: err=%v, want ErrVersionConflict", err)
	}
	m, err := s.Remove(ctx, "m", "bob", 1)
	if err != nil || m.Version != 2 {
		t.Fatalf("versioned remove: version=%d err=%v", m.Version, err)
	}
	if removed, _ := s.IsRemoved(ctx, "m", "bob"); !removed {
		t.Fatal("participant not marked removed")
	}
}

func TestMemAcquireShareVersionCheck(t *testing.T) {
	s := seedControl("m")
	ctx := context.Background()
	if _, _, err := s.AcquireShare(ctx, "m", "alice", "seg", 99); err != ErrVersionConflict {
		t.Fatalf("stale acquire: err=%v, want ErrVersionConflict", err)
	}
	holder, ok, err := s.AcquireShare(ctx, "m", "alice", "seg", 1)
	if err != nil || !ok || holder != "alice" {
		t.Fatalf("acquire: holder=%q ok=%v err=%v", holder, ok, err)
	}
	// A different user conflicts (holder disclosed), no error.
	if h, ok, err := s.AcquireShare(ctx, "m", "bob", "seg", 0); err != nil || ok || h != "alice" {
		t.Fatalf("conflict: holder=%q ok=%v err=%v", h, ok, err)
	}
}

func TestMemReleaseShareHolderRace(t *testing.T) {
	s := seedControl("m")
	ctx := context.Background()
	// alice holds the share.
	if _, _, err := s.AcquireShare(ctx, "m", "alice", "seg", 0); err != nil {
		t.Fatal(err)
	}
	// A stop-share authorized against "bob" (holder changed between check and
	// update) must NOT clear alice's share.
	if _, err := s.ReleaseShare(ctx, "m", "bob", 0); err != ErrVersionConflict {
		t.Fatalf("holder-race release: err=%v, want ErrVersionConflict", err)
	}
	if h, _ := s.ShareHolder(ctx, "m"); h != "alice" {
		t.Fatalf("holder cleared under race: %q", h)
	}
	// The correct holder clears it.
	if _, err := s.ReleaseShare(ctx, "m", "alice", 0); err != nil {
		t.Fatalf("release: %v", err)
	}
	if h, _ := s.ShareHolder(ctx, "m"); h != "" {
		t.Fatalf("holder not cleared: %q", h)
	}
}
