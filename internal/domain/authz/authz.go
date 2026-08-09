// Package authz encodes the meeting host/cohost/member (H/C/M) control
// authorization matrix (backend appendix §12). It is pure: handlers resolve the
// actor's role from the store and ask these predicates before mutating state, so
// the matrix is unit-tested independently of transport and persistence.
package authz

// Role is a participant's meeting role.
type Role string

// The three meeting roles.
const (
	Host   Role = "H"
	Cohost Role = "C"
	Member Role = "M"
)

// Valid reports whether r is one of the known roles.
func Valid(r Role) bool { return r == Host || r == Cohost || r == Member }

// CanLock reports whether the actor may lock/unlock the meeting (H or C).
func CanLock(actor Role) bool { return actor == Host || actor == Cohost }

// CanEnd reports whether the actor may end the meeting for everyone (H only).
func CanEnd(actor Role) bool { return actor == Host }

// CanEditOrCancel reports whether the actor may edit/cancel a scheduled meeting.
// Only the host (creator promoted to host) may, and only before live — the live
// check is enforced by the handler against meeting status.
func CanEditOrCancel(actor Role) bool { return actor == Host }

// CanSetRole reports whether the actor may assign/revoke cohost (H only; a
// cohost may not create or remove cohosts — FD-23).
func CanSetRole(actor Role) bool { return actor == Host }

// CanMute reports whether actor may mute target. The host manages cohosts and
// members; a cohost may operate on members only; a member may not mute others
// (members self-unmute via a different, unauthorized-by-role path).
func CanMute(actor, target Role) bool {
	switch actor {
	case Host:
		return target == Cohost || target == Member
	case Cohost:
		return target == Member
	default:
		return false
	}
}

// CanMuteAll reports whether the actor may mute everyone (H or C).
func CanMuteAll(actor Role) bool { return actor == Host || actor == Cohost }

// CanRemove reports whether actor may remove target. The host may remove a
// cohost or member; a cohost may remove members only; neither may remove the host.
func CanRemove(actor, target Role) bool {
	if target == Host {
		return false
	}
	switch actor {
	case Host:
		return target == Cohost || target == Member
	case Cohost:
		return target == Member
	default:
		return false
	}
}

// CanStopShare reports whether actor may stop a share currently held by holder.
// The host may stop any share; a cohost may stop its own or a member's; a member
// may stop only its own.
func CanStopShare(actor, holder Role, actorIsHolder bool) bool {
	if actorIsHolder {
		return true
	}
	switch actor {
	case Host:
		return true
	case Cohost:
		return holder == Member
	default:
		return false
	}
}
