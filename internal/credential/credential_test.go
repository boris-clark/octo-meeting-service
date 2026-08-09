package credential

import (
	"bytes"
	"regexp"
	"testing"
)

func testMinter(t *testing.T) *Minter {
	t.Helper()
	key := bytes.Repeat([]byte("k"), 32) // AES-256
	m, err := NewMinter([]byte("lookup-secret"), key)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

func TestNewMinterValidation(t *testing.T) {
	if _, err := NewMinter(nil, bytes.Repeat([]byte("k"), 32)); err == nil {
		t.Error("empty lookup secret must error")
	}
	if _, err := NewMinter([]byte("s"), []byte("short-key")); err == nil {
		t.Error("bad envelope key length must error")
	}
}

func TestGenerateNumberFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9]{9}$`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := GenerateNumber()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(n) {
			t.Fatalf("number %q not 9 digits", n)
		}
		seen[n] = true
	}
	// Random generation should not collapse to a constant.
	if len(seen) < 2 {
		t.Fatal("meeting numbers are not random")
	}
}

func TestGenerateLinkTokenUniqueHighEntropy(t *testing.T) {
	a, err := GenerateLinkToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateLinkToken()
	if a == b {
		t.Fatal("link tokens must not repeat")
	}
	if len(a) < 40 { // 32 bytes base64url ~ 43 chars
		t.Fatalf("link token too short: %d", len(a))
	}
}

func TestLookupHashDeterministicAndKeyed(t *testing.T) {
	m := testMinter(t)
	h1 := m.LookupHash("123456789")
	h2 := m.LookupHash("123456789")
	if !bytes.Equal(h1, h2) {
		t.Fatal("lookup hash must be deterministic")
	}
	if bytes.Equal(h1, m.LookupHash("987654321")) {
		t.Fatal("different inputs must hash differently")
	}
	// The raw value must not be recoverable from / equal to the hash.
	if bytes.Contains(h1, []byte("123456789")) {
		t.Fatal("lookup hash leaks the raw value")
	}
	// A minter with a different secret produces a different hash.
	other, _ := NewMinter([]byte("other-secret"), bytes.Repeat([]byte("k"), 32))
	if bytes.Equal(h1, other.LookupHash("123456789")) {
		t.Fatal("lookup hash must be keyed by the secret")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	m := testMinter(t)
	raw := "https://octo.example/join/abc123"
	sealed, err := m.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(raw)) {
		t.Fatal("sealed envelope contains plaintext")
	}
	// Two seals of the same value differ (random nonce).
	sealed2, _ := m.Seal(raw)
	if bytes.Equal(sealed, sealed2) {
		t.Fatal("envelope nonce is not random")
	}
	got, err := m.Open(sealed)
	if err != nil || got != raw {
		t.Fatalf("open = %q, %v; want %q", got, err, raw)
	}
	// Tampering is detected by the AEAD.
	sealed[len(sealed)-1] ^= 0xff
	if _, err := m.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext must fail to open")
	}
}
