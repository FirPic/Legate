package http

import (
	"testing"
)

func TestArgon2id_HashAndVerify(t *testing.T) {
	rawPass := "UltraSecretPassword#2026!"

	hash, err := HashPassword(rawPass)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if !IsArgon2idHash(hash) {
		t.Errorf("expected hash to have $argon2id$ prefix, got %q", hash)
	}

	// Verify correct password
	match, err := VerifyPassword(rawPass, hash)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if !match {
		t.Error("expected password to match its Argon2id hash")
	}

	// Verify wrong password
	matchWrong, err := VerifyPassword("WrongPassword123", hash)
	if err != nil {
		t.Fatalf("unexpected verification error on wrong password: %v", err)
	}
	if matchWrong {
		t.Error("expected wrong password to fail verification")
	}
}

func TestArgon2id_MalformedHashes(t *testing.T) {
	testCases := []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=2$salt$hash", // not argon2id
		"$argon2id$v=99$m=65536,t=3,p=2$salt$hash", // incompatible version
		"$argon2id$v=19$badparams$salt$hash",
		"$argon2id$v=19$m=65536,t=3,p=2$bad!salt$hash",
		"$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$bad!hash",
	}

	for _, tc := range testCases {
		_, err := VerifyPassword("secret", tc)
		if err == nil {
			t.Errorf("expected error for malformed hash %q, got nil", tc)
		}
	}
}
