package authz

import "testing"

func TestLockEndEditRole(t *testing.T) {
	if !CanLock(Host) || !CanLock(Cohost) || CanLock(Member) {
		t.Error("lock: H/C yes, M no")
	}
	if !CanEnd(Host) || CanEnd(Cohost) || CanEnd(Member) {
		t.Error("end: H only")
	}
	if !CanEditOrCancel(Host) || CanEditOrCancel(Cohost) || CanEditOrCancel(Member) {
		t.Error("edit/cancel: H only")
	}
	if !CanSetRole(Host) || CanSetRole(Cohost) || CanSetRole(Member) {
		t.Error("set role: H only")
	}
	if !CanMuteAll(Host) || !CanMuteAll(Cohost) || CanMuteAll(Member) {
		t.Error("mute all: H/C yes, M no")
	}
}

func TestCanMute(t *testing.T) {
	// Host manages cohosts and members; never a no-op on itself matters here.
	if !CanMute(Host, Member) || !CanMute(Host, Cohost) {
		t.Error("host mutes member and cohost")
	}
	// Cohost operates on members only.
	if !CanMute(Cohost, Member) {
		t.Error("cohost mutes member")
	}
	if CanMute(Cohost, Cohost) || CanMute(Cohost, Host) {
		t.Error("cohost must not mute cohost/host")
	}
	// Members may not mute others.
	if CanMute(Member, Member) {
		t.Error("member must not mute others")
	}
}

func TestCanRemove(t *testing.T) {
	if !CanRemove(Host, Member) || !CanRemove(Host, Cohost) {
		t.Error("host removes member and cohost")
	}
	if !CanRemove(Cohost, Member) {
		t.Error("cohost removes member")
	}
	if CanRemove(Cohost, Cohost) {
		t.Error("cohost must not remove cohost")
	}
	// The host is never removable, and members cannot remove.
	if CanRemove(Host, Host) || CanRemove(Cohost, Host) || CanRemove(Member, Member) {
		t.Error("host not removable; members cannot remove")
	}
}

func TestCanStopShare(t *testing.T) {
	// Anyone can stop their own share.
	if !CanStopShare(Member, Member, true) {
		t.Error("member stops own share")
	}
	// Host stops any; cohost stops member's; member cannot stop others'.
	if !CanStopShare(Host, Cohost, false) {
		t.Error("host stops any share")
	}
	if !CanStopShare(Cohost, Member, false) {
		t.Error("cohost stops a member's share")
	}
	if CanStopShare(Cohost, Host, false) {
		t.Error("cohost must not stop the host's share")
	}
	if CanStopShare(Member, Cohost, false) {
		t.Error("member must not stop another's share")
	}
}

func TestValid(t *testing.T) {
	if !Valid(Host) || !Valid(Cohost) || !Valid(Member) || Valid(Role("X")) {
		t.Error("role validity")
	}
}
