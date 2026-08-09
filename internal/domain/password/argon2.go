package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params configures Argon2id hashing (OD-08: Argon2id is the default
// verifier). The parameters are encoded into the stored verifier so they can be
// tuned/rotated without breaking existing rows.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// DefaultArgon2Params returns interactive-grade parameters suitable for a
// 6-digit verifier gated by a per-user+meeting cooldown.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 2, KeyLen: 32, SaltLen: 16}
}

// Algorithm is the verifier algorithm label persisted alongside the encoded
// verifier.
const Algorithm = "argon2id"

// Hash derives a PHC-encoded Argon2id verifier for the password with a fresh
// random salt. The returned string embeds the parameters and salt; the raw
// password is never stored. An optional pepper (from secret config) is
// prepended to the password before hashing and is NOT stored.
func (p Argon2Params) Hash(password, pepper string) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("argon2: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pepper+password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyArgon2 reports whether the password matches the PHC-encoded verifier.
// The comparison is constant-time. The pepper must match the one used at Hash.
func VerifyArgon2(encoded, pepper, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != Algorithm {
		return false, fmt.Errorf("argon2: malformed verifier")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("argon2: version: %w", err)
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("argon2: params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("argon2: salt decode: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("argon2: hash decode: %w", err)
	}
	keyLen := len(want)
	if keyLen <= 0 || keyLen > 1024 {
		return false, fmt.Errorf("argon2: invalid key length %d", keyLen)
	}
	got := argon2.IDKey([]byte(pepper+password), salt, time, memory, threads, uint32(keyLen))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
