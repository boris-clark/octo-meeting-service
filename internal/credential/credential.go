// Package credential mints and protects meeting credentials: the user-facing
// 6-digit meeting number and the high-entropy join link token. At rest, the
// service stores only an HMAC lookup hash (for indexed lookup) and an AES-GCM
// envelope ciphertext (for authorized display) — never the raw value. This keeps
// meeting numbers unguessable-at-rest and link tokens secret while still
// supporting O(1) resolution.
package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

// NumberDigits is the fixed meeting-number length (OD-03 default: fixed-length
// numeric, random, hash-stored).
const NumberDigits = 9

// linkTokenBytes is the entropy of a join link token before encoding.
const linkTokenBytes = 32

// Minter generates and protects credentials. The lookupSecret keys the HMAC
// used for at-rest lookup hashes; the envelope AEAD protects display material.
type Minter struct {
	lookupSecret []byte
	aead         cipher.AEAD
}

// NewMinter builds a Minter. The envelope key must be 16, 24, or 32 bytes
// (AES-128/192/256). An empty lookup secret is rejected — resolution and
// at-rest protection both depend on it.
func NewMinter(lookupSecret, envelopeKey []byte) (*Minter, error) {
	if len(lookupSecret) == 0 {
		return nil, fmt.Errorf("credential: empty lookup secret")
	}
	block, err := aes.NewCipher(envelopeKey)
	if err != nil {
		return nil, fmt.Errorf("credential: envelope key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credential: gcm: %w", err)
	}
	return &Minter{lookupSecret: append([]byte(nil), lookupSecret...), aead: aead}, nil
}

// GenerateNumber returns a fixed-length, uniformly random numeric meeting
// number. It is unpredictable (crypto/rand) so numbers cannot be enumerated by
// counting.
func GenerateNumber() (string, error) {
	const maxExclusive = 1_000_000_000 // 10^9, matches NumberDigits=9
	n, err := randUint32Below(maxExclusive)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", NumberDigits, n), nil
}

// GenerateLinkToken returns a high-entropy, URL-safe join link token.
func GenerateLinkToken() (string, error) {
	buf := make([]byte, linkTokenBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("credential: link token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LookupHash returns HMAC-SHA256(lookupSecret, value): the only material stored
// for indexed credential lookup. It is deterministic so the same value always
// maps to the same row.
func (m *Minter) LookupHash(value string) []byte {
	mac := hmac.New(sha256.New, m.lookupSecret)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// Seal envelope-encrypts a raw credential for authorized display. The nonce is
// prepended to the ciphertext. The raw value never leaves this envelope at rest.
func (m *Minter) Seal(raw string) ([]byte, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("credential: nonce: %w", err)
	}
	return m.aead.Seal(nonce, nonce, []byte(raw), nil), nil
}

// Open decrypts an envelope produced by Seal. It is only called on authorized
// display paths.
func (m *Minter) Open(sealed []byte) (string, error) {
	ns := m.aead.NonceSize()
	if len(sealed) < ns {
		return "", fmt.Errorf("credential: ciphertext too short")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	pt, err := m.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("credential: open: %w", err)
	}
	return string(pt), nil
}

// randUint32Below returns a uniformly random integer in [0, max) without modulo
// bias, using rejection sampling over crypto/rand.
func randUint32Below(max uint32) (uint32, error) {
	// Largest multiple of max that fits in uint32; values at/above are rejected.
	limit := (1 << 32) - ((1 << 32) % uint64(max))
	var buf [4]byte
	for {
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return 0, fmt.Errorf("credential: rand: %w", err)
		}
		v := binary.BigEndian.Uint32(buf[:])
		if uint64(v) < limit {
			return v % max, nil
		}
	}
}
