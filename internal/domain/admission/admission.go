// Package admission implements the server-authoritative admission oracle: the
// fixed FD-27 step-1 predicate order, the S-1 cross-Space enumeration envelope,
// and the allowed_to_prejoin truth table (architecture §7.2 / backend appendix
// §5.1).
//
// The logic here is pure and deterministic: it takes already-resolved facts and
// returns a decision. Both admission/evaluate and admission/finalize call
// Evaluate so the two paths cannot diverge. Fetching facts (credential
// resolution, Space seam, capacity, pass-token validity) happens in the caller;
// this package never performs I/O.
package admission

import "github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"

// MeetingFacts are the resolved, server-side facts about a meeting needed to
// decide admission. They are authoritative (DB/seam derived), never client
// supplied.
type MeetingFacts struct {
	// Exists is true when the credential resolved to a real meeting.
	Exists bool
	// Ended/Cancelled/Locked/Full are lifecycle/state predicates.
	Ended     bool
	Cancelled bool
	Locked    bool
	Full      bool
	// WithinEarlyJoinWindow is true when now >= scheduled_start_at -
	// MEETING_EARLY_JOIN_WINDOW_SECONDS (evaluated by the caller against the
	// server clock; see package meeting).
	WithinEarlyJoinWindow bool
	// PasswordEnabled reflects whether the meeting requires a password.
	PasswordEnabled bool
}

// CallerFacts are the resolved facts about the caller relative to the meeting.
type CallerFacts struct {
	// SameSpaceActiveMember is true when the caller is an active member of the
	// meeting's Space (resolved via the Space seam).
	SameSpaceActiveMember bool
	// IsCreator/IsInvitee/IsParticipant establish that the caller is already
	// authorized to know the meeting exists.
	IsCreator     bool
	IsInvitee     bool
	IsParticipant bool
	// Removed is true when a terminal removal record exists for the caller.
	Removed bool
	// HasValidPassToken is true when the caller holds a TTL-valid
	// password_pass_token OR qualifies for the same-endpoint 15s reconnect grace
	// (both resolved upstream).
	HasValidPassToken bool
}

// Decision is the outcome of the oracle. When Eligible is false, Error carries
// the single stable code to return and the disposition fields are meaningless
// (the handler must not serialize them). When Eligible is true, PasswordRequired
// and AllowedToPrejoin are authoritative.
type Decision struct {
	Eligible         bool
	Error            merr.Code
	PasswordRequired bool
	AllowedToPrejoin bool
}

// authorizedToKnow implements the S-1 envelope: a caller may only learn that a
// meeting exists if they are an active member of its Space, or are its creator,
// an invitee, or an existing participant. A non-existent meeting is never
// knowable.
func authorizedToKnow(m MeetingFacts, c CallerFacts) bool {
	if !m.Exists {
		return false
	}
	return c.SameSpaceActiveMember || c.IsCreator || c.IsInvitee || c.IsParticipant
}

// Evaluate applies the S-1 envelope and then the fixed FD-27 step-1 order,
// returning the first failing predicate. On success it fills the
// allowed_to_prejoin truth table. The creator is exempt from the password on
// their own meeting.
func Evaluate(m MeetingFacts, c CallerFacts) Decision {
	// S-1: unauthorized callers (typically cross-Space number/link guesses) get
	// an indistinguishable 404 regardless of the meeting's real state. This also
	// folds the non-existent case, so existence is never leaked.
	if !authorizedToKnow(m, c) {
		return Decision{Error: merr.CredentialInvalid}
	}

	// FD-27 step-1, fixed order; first failure wins.
	switch {
	case m.Ended:
		return Decision{Error: merr.Ended}
	case m.Cancelled:
		return Decision{Error: merr.Cancelled}
	case m.Locked:
		return Decision{Error: merr.Locked}
	case m.Full:
		return Decision{Error: merr.Full}
	case c.Removed:
		return Decision{Error: merr.Removed}
	case !m.WithinEarlyJoinWindow:
		return Decision{Error: merr.TooEarly}
	case !c.SameSpaceActiveMember:
		// Reached only by an authorized-to-know caller (creator/invitee/
		// participant) who is nonetheless not an active same-Space member.
		return Decision{Error: merr.NotSameSpace}
	}

	// Eligible. Resolve the password disposition. The creator is exempt on their
	// own meeting; a valid pass token (incl. the 15s reconnect grace) also
	// satisfies the requirement.
	exempt := c.IsCreator || c.HasValidPassToken
	passwordRequired := m.PasswordEnabled && !exempt
	return Decision{
		Eligible:         true,
		PasswordRequired: passwordRequired,
		AllowedToPrejoin: !passwordRequired,
	}
}
