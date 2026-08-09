package admission

import (
	"testing"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
)

// eligibleMeeting/eligibleCaller are the baseline "everything passes" facts;
// tests flip individual fields.
func eligibleMeeting() MeetingFacts {
	return MeetingFacts{Exists: true, WithinEarlyJoinWindow: true}
}

func eligibleCaller() CallerFacts {
	return CallerFacts{SameSpaceActiveMember: true}
}

func TestS1UnauthorizedAlwaysCredentialInvalid(t *testing.T) {
	// An unauthorized (not same-Space, not creator/invitee/participant) caller
	// must get MEETING_CREDENTIAL_INVALID for every underlying meeting state, so
	// it is indistinguishable from a non-existent meeting.
	states := []func(*MeetingFacts){
		func(m *MeetingFacts) {},
		func(m *MeetingFacts) { m.Ended = true },
		func(m *MeetingFacts) { m.Cancelled = true },
		func(m *MeetingFacts) { m.Locked = true },
		func(m *MeetingFacts) { m.Full = true },
		func(m *MeetingFacts) { m.WithinEarlyJoinWindow = false },
		func(m *MeetingFacts) { m.PasswordEnabled = true },
	}
	for i, mutate := range states {
		m := eligibleMeeting()
		mutate(&m)
		d := Evaluate(m, CallerFacts{}) // unauthorized caller
		if d.Eligible || d.Error != merr.CredentialInvalid {
			t.Errorf("state %d: got %+v, want CredentialInvalid", i, d)
		}
	}
}

func TestNonExistentIsCredentialInvalidEvenForCreator(t *testing.T) {
	d := Evaluate(MeetingFacts{Exists: false}, CallerFacts{IsCreator: true})
	if d.Error != merr.CredentialInvalid {
		t.Fatalf("got %v, want CredentialInvalid", d.Error)
	}
}

func TestFD27FirstFailureWins(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MeetingFacts, *CallerFacts)
		want   merr.Code
	}{
		{"removed+cross-space -> removed", func(m *MeetingFacts, c *CallerFacts) {
			c.IsParticipant = true // authorized to know
			c.Removed = true
			c.SameSpaceActiveMember = false
		}, merr.Removed},
		{"locked+full+removed -> locked", func(m *MeetingFacts, c *CallerFacts) {
			m.Locked = true
			m.Full = true
			c.Removed = true
		}, merr.Locked},
		{"too-early+cross-space -> too-early", func(m *MeetingFacts, c *CallerFacts) {
			c.IsInvitee = true
			m.WithinEarlyJoinWindow = false
			c.SameSpaceActiveMember = false
		}, merr.TooEarly},
		{"ended before cancelled", func(m *MeetingFacts, c *CallerFacts) {
			m.Ended = true
			m.Cancelled = true
		}, merr.Ended},
		{"cross-space authorized creator -> not_same_space", func(m *MeetingFacts, c *CallerFacts) {
			c.IsCreator = true
			c.SameSpaceActiveMember = false
		}, merr.NotSameSpace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := eligibleMeeting()
			c := eligibleCaller()
			tt.mutate(&m, &c)
			d := Evaluate(m, c)
			if d.Eligible {
				t.Fatalf("expected ineligible, got eligible")
			}
			if d.Error != tt.want {
				t.Fatalf("got %v, want %v", d.Error, tt.want)
			}
		})
	}
}

func TestAllowedToPrejoinTruthTable(t *testing.T) {
	tests := []struct {
		name              string
		passwordEnabled   bool
		hasValidPassToken bool
		isCreator         bool
		wantRequired      bool
		wantPrejoin       bool
	}{
		{"no password", false, false, false, false, true},
		{"password, no pass token", true, false, false, true, false},
		{"password, valid pass token (incl 15s grace)", true, true, false, false, true},
		{"password, creator exemption", true, false, true, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := eligibleMeeting()
			m.PasswordEnabled = tt.passwordEnabled
			c := eligibleCaller()
			c.HasValidPassToken = tt.hasValidPassToken
			c.IsCreator = tt.isCreator
			d := Evaluate(m, c)
			if !d.Eligible {
				t.Fatalf("expected eligible, got %+v", d)
			}
			if d.PasswordRequired != tt.wantRequired {
				t.Errorf("password_required = %v, want %v", d.PasswordRequired, tt.wantRequired)
			}
			if d.AllowedToPrejoin != tt.wantPrejoin {
				t.Errorf("allowed_to_prejoin = %v, want %v", d.AllowedToPrejoin, tt.wantPrejoin)
			}
			// Invariant: allowed_to_prejoin == eligible AND NOT password_required.
			if d.AllowedToPrejoin != (d.Eligible && !d.PasswordRequired) {
				t.Errorf("truth-table invariant violated: %+v", d)
			}
		})
	}
}

func TestSameSpaceMemberMayDiscoverViaGuess(t *testing.T) {
	// A same-Space active member is authorized to know the meeting exists, so a
	// number/link lookup returns the real state (here: ended), not a 404.
	m := eligibleMeeting()
	m.Ended = true
	c := CallerFacts{SameSpaceActiveMember: true}
	if d := Evaluate(m, c); d.Error != merr.Ended {
		t.Fatalf("got %v, want Ended for same-Space member", d.Error)
	}
}
