// Package livekit implements the control-plane pieces the meeting service owns:
// minting short-lived, least-privilege LiveKit access tokens and verifying
// inbound LiveKit webhook signatures. Tokens are LiveKit-compatible HS256 JWTs
// built with the standard library (no third-party SDK, to keep the dependency
// and vulnerability surface minimal). No secret — API secret, password, raw link
// token — is ever placed in a claim or logged.
package livekit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Grant is the least-privilege video grant embedded in an access token.
type Grant struct {
	Room         string `json:"room"`
	RoomJoin     bool   `json:"roomJoin"`
	CanPublish   bool   `json:"canPublish"`
	CanSubscribe bool   `json:"canSubscribe"`
}

// Claims are the non-sensitive business bindings carried in token metadata.
// Only hashed/opaque identifiers are included — never a raw uid, password, or
// link token.
type Claims struct {
	MeetingID   string `json:"meeting_id"`
	SegmentID   string `json:"participant_segment_id"`
	UIDHash     string `json:"uid_hash"`
	Role        string `json:"role"`
	SpaceIDHash string `json:"space_id_hash"`
}

// Minter builds access tokens bound to the configured API key/secret and TTL.
type Minter struct {
	apiKey    string
	apiSecret string
	ttl       time.Duration
}

// NewMinter builds a Minter. ttl must be > 0.
func NewMinter(apiKey, apiSecret string, ttl time.Duration) (*Minter, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("livekit: api key and secret are required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("livekit: ttl must be positive")
	}
	return &Minter{apiKey: apiKey, apiSecret: apiSecret, ttl: ttl}, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type accessClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Nbf      int64  `json:"nbf"`
	Exp      int64  `json:"exp"`
	Jti      string `json:"jti"`
	Video    Grant  `json:"video"`
	Metadata string `json:"metadata"`
}

// Mint issues a signed access token for the given identity. now is injected so
// nbf/exp are deterministic in tests. The jti is random for replay resistance.
func (m *Minter) Mint(identity string, grant Grant, claims Claims, now time.Time) (string, error) {
	if identity == "" {
		return "", fmt.Errorf("livekit: empty identity")
	}
	meta, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("livekit: marshal metadata: %w", err)
	}
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	payload := accessClaims{
		Iss:      m.apiKey,
		Sub:      identity,
		Nbf:      now.Add(-5 * time.Second).Unix(),
		Exp:      now.Add(m.ttl).Unix(),
		Jti:      jti,
		Video:    grant,
		Metadata: string(meta),
	}
	return sign(m.apiSecret, jwtHeader{Alg: "HS256", Typ: "JWT"}, payload)
}

func sign(secret string, header jwtHeader, payload any) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(pb)
	sig := hmacSHA256([]byte(signingInput), []byte(secret))
	return signingInput + "." + b64(sig), nil
}

func hmacSHA256(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("livekit: random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// constantTimeEqual compares two byte slices without leaking length-independent
// timing.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
