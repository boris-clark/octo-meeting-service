package api

import (
	"time"

	"github.com/Jerry-Xin/octo-meeting-service/internal/livekit"
)

// LiveKitMinter adapts *livekit.Minter to the TokenMinter interface used by the
// admission service.
type LiveKitMinter struct {
	M *livekit.Minter
}

// MintAccess builds a least-privilege join grant and mints a token. The claims
// map carries only non-sensitive hashed identifiers.
func (a LiveKitMinter) MintAccess(room, identity, role string, claims map[string]string, now time.Time) (string, error) {
	grant := livekit.Grant{
		Room:         room,
		RoomJoin:     true,
		CanPublish:   true,
		CanSubscribe: true,
	}
	return a.M.Mint(identity, grant, livekit.Claims{
		MeetingID:   claims["meeting_id"],
		SegmentID:   claims["participant_segment_id"],
		UIDHash:     claims["uid_hash"],
		Role:        role,
		SpaceIDHash: claims["space_id_hash"],
	}, now)
}

// compile-time assertion.
var _ TokenMinter = LiveKitMinter{}
