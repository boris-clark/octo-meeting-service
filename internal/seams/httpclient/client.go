// Package httpclient provides concrete, fail-closed HTTP implementations of the
// seam interfaces (auth token verify, Space membership verify, notification
// dispatch). Every client is audience-bound via an internal service token,
// bounded by a timeout, and fails closed: a transport error, timeout, non-2xx
// status, or malformed body is surfaced as an error so callers never proceed on
// uncertainty. Browser-supplied identity (x-user-id / x-org-id) is never sent or
// trusted; identity flows only from the verified auth seam response.
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

// maxBody caps how much of a seam response we read, defending against a
// misbehaving upstream.
const maxBody = 1 << 20 // 1 MiB

// Options configure a seam client.
type Options struct {
	BaseURL string
	// ServiceToken is the audience-bound internal service credential. It is sent
	// as a bearer on every seam call and never logged.
	ServiceToken string
	// HTTPClient carries the timeout; callers pass a client built from the
	// configured seam timeout.
	HTTPClient *http.Client
}

func (o Options) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return http.DefaultClient
}

// AuthClient verifies a bearer credential against the auth seam.
type AuthClient struct{ opts Options }

// NewAuthClient builds an AuthClient.
func NewAuthClient(o Options) *AuthClient { return &AuthClient{opts: o} }

type authResponse struct {
	UserID string `json:"uid"`
	OrgID  string `json:"org_id"`
}

// Authenticate resolves a verified Principal or fails closed. The browser bearer
// is forwarded for verification; the returned identity comes only from the seam.
func (c *AuthClient) Authenticate(ctx context.Context, bearer string) (*seams.Principal, error) {
	if bearer == "" {
		return nil, fmt.Errorf("auth seam: empty credential")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.BaseURL+"/verify", nil)
	if err != nil {
		return nil, fmt.Errorf("auth seam: build request: %w", err)
	}
	req.Header.Set("X-Verify-Token", bearer)
	var out authResponse
	if err := c.do(req, &out); err != nil {
		return nil, fmt.Errorf("auth seam: %w", err)
	}
	if out.UserID == "" {
		return nil, fmt.Errorf("auth seam: verified identity missing uid")
	}
	return &seams.Principal{UserID: out.UserID, OrgID: out.OrgID}, nil
}

func (c *AuthClient) do(req *http.Request, out any) error {
	return do(c.opts, req, out)
}

// SpaceClient verifies active Space membership.
type SpaceClient struct{ opts Options }

// NewSpaceClient builds a SpaceClient.
func NewSpaceClient(o Options) *SpaceClient { return &SpaceClient{opts: o} }

type spaceResponse struct {
	Member bool `json:"member"`
}

// IsMember reports active membership, failing closed (not a member) on any
// error, timeout, or uncertain response. The error is returned so the caller can
// distinguish a definitive "not a member" from an infrastructure failure, but in
// both cases admission must treat the caller as unauthorized.
func (c *SpaceClient) IsMember(ctx context.Context, orgID, userID string) (bool, error) {
	body, err := json.Marshal(map[string]string{"org_id": orgID, "uid": userID})
	if err != nil {
		return false, fmt.Errorf("space seam: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.BaseURL+"/membership", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("space seam: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	var out spaceResponse
	if err := do(c.opts, req, &out); err != nil {
		return false, fmt.Errorf("space seam: %w", err)
	}
	return out.Member, nil
}

// NotificationClient dispatches a redacted notification intent.
type NotificationClient struct{ opts Options }

// NewNotificationClient builds a NotificationClient.
func NewNotificationClient(o Options) *NotificationClient { return &NotificationClient{opts: o} }

// Notify sends a redacted notification. The payload must already be free of
// secrets (no raw password, link token, or LiveKit token). A delivery failure is
// returned so the caller can record MEETING_NOTIFICATION_DEFERRED without rolling
// back the meeting change.
func (c *NotificationClient) Notify(ctx context.Context, userID, template string, payload map[string]any) error {
	body, err := json.Marshal(map[string]any{"uid": userID, "template": template, "payload": payload})
	if err != nil {
		return fmt.Errorf("notification seam: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.BaseURL+"/dispatch", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notification seam: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := do(c.opts, req, nil); err != nil {
		return fmt.Errorf("notification seam: %w", err)
	}
	return nil
}

// do executes a seam request with the internal service credential and decodes a
// 2xx JSON body into out (out may be nil to ignore the body). Any non-2xx status
// or transport error is returned so the caller fails closed.
func do(opts Options, req *http.Request, out any) error {
	if opts.ServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.ServiceToken)
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// Compile-time assertions that the clients satisfy the seam interfaces.
var (
	_ seams.Auth         = (*AuthClient)(nil)
	_ seams.Space        = (*SpaceClient)(nil)
	_ seams.Notification = (*NotificationClient)(nil)
)
