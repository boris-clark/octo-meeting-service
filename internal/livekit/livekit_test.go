package livekit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMintProducesVerifiableToken(t *testing.T) {
	m, err := NewMinter("APIkey", "secret-value", 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	tok, err := m.Mint("seg-identity", Grant{Room: "octo-meeting-abc", RoomJoin: true, CanSubscribe: true},
		Claims{MeetingID: "mtg-1", SegmentID: "seg-1", UIDHash: "uh", Role: "M", SpaceIDHash: "sh"}, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token not a 3-part JWT: %q", tok)
	}
	// Signature must verify with the same secret.
	expected := hmacSHA256([]byte(parts[0]+"."+parts[1]), []byte("secret-value"))
	if b64(expected) != parts[2] {
		t.Fatal("signature does not verify")
	}
	// Claims: iss=apiKey, sub=identity, exp=now+ttl, and grant present.
	claimJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c accessClaims
	if err := json.Unmarshal(claimJSON, &c); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	if c.Iss != "APIkey" || c.Sub != "seg-identity" {
		t.Errorf("iss/sub = %q/%q", c.Iss, c.Sub)
	}
	if c.Exp != now.Add(90*time.Second).Unix() {
		t.Errorf("exp = %d, want now+90s", c.Exp)
	}
	if !c.Video.RoomJoin || c.Video.Room != "octo-meeting-abc" {
		t.Errorf("grant = %+v", c.Video)
	}
	// The API secret must never appear anywhere in the token.
	if strings.Contains(tok, "secret-value") {
		t.Fatal("secret leaked into token")
	}
}

func TestMintRejectsEmptyIdentityAndBadConfig(t *testing.T) {
	if _, err := NewMinter("", "s", time.Second); err == nil {
		t.Error("empty api key must error")
	}
	if _, err := NewMinter("k", "s", 0); err == nil {
		t.Error("non-positive ttl must error")
	}
	m, _ := NewMinter("k", "s", time.Second)
	if _, err := m.Mint("", Grant{}, Claims{}, time.Now()); err == nil {
		t.Error("empty identity must error")
	}
}

// signWebhook builds a LiveKit-style webhook Authorization token for tests.
func signWebhook(t *testing.T, secret string, body []byte, exp int64) string {
	t.Helper()
	sum := sha256.Sum256(body)
	claims := webhookClaims{Iss: "APIkey", Exp: exp, Sha256: base64.StdEncoding.EncodeToString(sum[:])}
	tok, err := sign(secret, jwtHeader{Alg: "HS256", Typ: "JWT"}, claims)
	if err != nil {
		t.Fatalf("signWebhook: %v", err)
	}
	return tok
}

func TestWebhookVerifyValid(t *testing.T) {
	v, err := NewWebhookVerifier("APIkey", "whsecret", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"event":"participant_left","room":{"name":"octo-meeting-abc"}}`)
	tok := signWebhook(t, "whsecret", body, now.Add(time.Minute).Unix())
	if err := v.Verify("Bearer "+tok, body, now); err != nil {
		t.Fatalf("valid webhook rejected: %v", err)
	}
}

func TestWebhookVerifyRejectsTamperedBody(t *testing.T) {
	v, _ := NewWebhookVerifier("APIkey", "whsecret", 5*time.Minute)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"event":"participant_left"}`)
	tok := signWebhook(t, "whsecret", body, now.Add(time.Minute).Unix())
	if err := v.Verify("Bearer "+tok, []byte(`{"event":"room_finished"}`), now); err == nil {
		t.Fatal("tampered body must be rejected")
	}
}

func TestWebhookVerifyRejectsWrongSecretAndExpiry(t *testing.T) {
	v, _ := NewWebhookVerifier("APIkey", "whsecret", 0)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"event":"x"}`)

	wrong := signWebhook(t, "attacker", body, now.Add(time.Minute).Unix())
	if err := v.Verify("Bearer "+wrong, body, now); err == nil {
		t.Fatal("wrong secret must be rejected")
	}

	expired := signWebhook(t, "whsecret", body, now.Add(-time.Minute).Unix())
	if err := v.Verify("Bearer "+expired, body, now); err == nil {
		t.Fatal("expired token must be rejected")
	}

	if err := v.Verify("", body, now); err == nil {
		t.Fatal("missing header must be rejected")
	}
}
