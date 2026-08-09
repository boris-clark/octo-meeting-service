package password

import "testing"

func TestArgon2HashVerify(t *testing.T) {
	p := DefaultArgon2Params()
	enc, err := p.Hash("424242", "pepper-1")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// The encoded verifier must not contain the raw password or be reversible.
	if enc == "424242" || len(enc) < 40 {
		t.Fatalf("suspicious verifier: %q", enc)
	}

	ok, err := VerifyArgon2(enc, "pepper-1", "424242")
	if err != nil || !ok {
		t.Fatalf("correct password: ok=%v err=%v, want true", ok, err)
	}

	if ok, _ := VerifyArgon2(enc, "pepper-1", "000000"); ok {
		t.Fatal("wrong password verified true")
	}
	// A different pepper must fail (pepper binds the verifier to secret config).
	if ok, _ := VerifyArgon2(enc, "pepper-2", "424242"); ok {
		t.Fatal("wrong pepper verified true")
	}
}

func TestArgon2SaltIsRandom(t *testing.T) {
	p := DefaultArgon2Params()
	a, _ := p.Hash("424242", "")
	b, _ := p.Hash("424242", "")
	if a == b {
		t.Fatal("same password produced identical verifiers (salt not random)")
	}
}

func TestVerifyArgon2Malformed(t *testing.T) {
	for _, bad := range []string{"", "plain", "$argon2id$bad", "$bcrypt$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"} {
		if _, err := VerifyArgon2(bad, "", "x"); err == nil {
			t.Errorf("VerifyArgon2(%q) expected error", bad)
		}
	}
}
