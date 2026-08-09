// Package seams defines the interfaces for external systems the meeting service
// integrates with: authentication, Space membership, notifications, and the
// LiveKit realtime backend.
//
// The bootstrap ships interfaces plus a "not implemented" default so wiring and
// health surfaces compile without making any live calls. Concrete clients are
// added when the corresponding domain work lands. Identity is always derived
// from an authenticated principal resolved by the Auth seam — never from
// client-supplied headers such as x-user-id / x-org-id.
package seams

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by the bootstrap default clients.
var ErrNotImplemented = errors.New("seam client not implemented in bootstrap")

// Principal is the authenticated identity resolved from a bearer credential.
// It is the only trusted source of user/org identity in the service.
type Principal struct {
	UserID string
	OrgID  string
}

// Auth resolves a verified credential into a Principal. Callers must never
// trust identity supplied directly by the browser.
type Auth interface {
	Authenticate(ctx context.Context, bearer string) (*Principal, error)
}

// Space answers membership and permission questions for an organization Space.
type Space interface {
	IsMember(ctx context.Context, orgID, userID string) (bool, error)
}

// Notification delivers out-of-band notifications (invites, reminders).
type Notification interface {
	Notify(ctx context.Context, userID, template string, payload map[string]any) error
}

// LiveKit mints scoped realtime access. Tokens produced here are secrets and
// must never be logged.
type LiveKit interface {
	IssueAccessToken(ctx context.Context, room, identity string, ttlSeconds int) (string, error)
}
