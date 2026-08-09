package seams

import "context"

// Unconfigured is the bootstrap default that satisfies every seam interface by
// returning ErrNotImplemented. It lets the service wire and boot without any
// live external calls. Replace each with a concrete client as domain work lands.
type Unconfigured struct{}

// Authenticate implements Auth.
func (Unconfigured) Authenticate(context.Context, string) (*Principal, error) {
	return nil, ErrNotImplemented
}

// IsMember implements Space.
func (Unconfigured) IsMember(context.Context, string, string) (bool, error) {
	return false, ErrNotImplemented
}

// Notify implements Notification.
func (Unconfigured) Notify(context.Context, string, string, map[string]any) error {
	return ErrNotImplemented
}

// IssueAccessToken implements LiveKit.
func (Unconfigured) IssueAccessToken(context.Context, string, string, int) (string, error) {
	return "", ErrNotImplemented
}

// Compile-time assertions that Unconfigured satisfies every seam.
var (
	_ Auth         = Unconfigured{}
	_ Space        = Unconfigured{}
	_ Notification = Unconfigured{}
	_ LiveKit      = Unconfigured{}
)
