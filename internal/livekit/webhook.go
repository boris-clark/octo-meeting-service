package livekit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WebhookVerifier authenticates inbound LiveKit webhooks. LiveKit signs the
// request with an Authorization JWT (HS256, API secret) whose `sha256` claim is
// the base64 digest of the raw body. Verification checks the signature, the time
// window, and that the body digest matches — so a replayed or tampered body is
// rejected. The webhook is used only for reconciliation, never as the sole
// source of lifecycle truth.
type WebhookVerifier struct {
	apiKey    string
	apiSecret string
	tolerance time.Duration
}

// NewWebhookVerifier builds a verifier. tolerance bounds clock skew on exp/nbf.
func NewWebhookVerifier(apiKey, apiSecret string, tolerance time.Duration) (*WebhookVerifier, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("livekit: api key and secret are required")
	}
	if tolerance < 0 {
		return nil, fmt.Errorf("livekit: tolerance must be non-negative")
	}
	return &WebhookVerifier{apiKey: apiKey, apiSecret: apiSecret, tolerance: tolerance}, nil
}

type webhookClaims struct {
	Iss    string `json:"iss"`
	Exp    int64  `json:"exp"`
	Nbf    int64  `json:"nbf"`
	Sha256 string `json:"sha256"`
}

// Verify authenticates the Authorization header against the raw request body at
// time now. It returns nil only when the signature is valid, the token is within
// its time window, and the body digest matches.
func (v *WebhookVerifier) Verify(authHeader string, body []byte, now time.Time) error {
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		return fmt.Errorf("livekit webhook: missing authorization")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("livekit webhook: malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	expected := hmacSHA256([]byte(signingInput), []byte(v.apiSecret))
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("livekit webhook: bad signature encoding")
	}
	if !constantTimeEqual(expected, got) {
		return fmt.Errorf("livekit webhook: signature mismatch")
	}

	claimJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("livekit webhook: bad claims encoding")
	}
	var claims webhookClaims
	if err := json.Unmarshal(claimJSON, &claims); err != nil {
		return fmt.Errorf("livekit webhook: bad claims: %w", err)
	}

	if claims.Exp != 0 && now.After(time.Unix(claims.Exp, 0).Add(v.tolerance)) {
		return fmt.Errorf("livekit webhook: token expired")
	}
	if claims.Nbf != 0 && now.Add(v.tolerance).Before(time.Unix(claims.Nbf, 0)) {
		return fmt.Errorf("livekit webhook: token not yet valid")
	}

	sum := sha256.Sum256(body)
	wantDigest := base64.StdEncoding.EncodeToString(sum[:])
	if !constantTimeEqual([]byte(wantDigest), []byte(claims.Sha256)) {
		return fmt.Errorf("livekit webhook: body digest mismatch")
	}
	return nil
}
