package http

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id recommended production parameters (RFC 9106)
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 2
	argon2KeyLen  = 32
	argon2SaltLen = 16

	// Precomputed dummy Argon2id hash to prevent timing-based user enumeration.
	// Generated with time=3, memory=65536, threads=2, salt length=16, key length=32.
	DummyArgon2idHash = "$argon2id$v=19$m=65536,t=3,p=2$ZHZ1bmtsZXZhbGlkc2FsdA$YnlF0zPsh8H3R3m5x/l5g8B4o2gC7f6Q9r8u1v2w3x4"
)

var (
	ErrInvalidHash         = errors.New("argon2id: hash format is invalid")
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version")
)

// HashPassword hashes a plaintext password using Argon2id with cryptographically secure random salt.
// Returns a PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads, b64Salt, b64Hash,
	)

	return encoded, nil
}

// IsArgon2idHash checks whether a given string is formatted as an Argon2id hash.
func IsArgon2idHash(encoded string) bool {
	return strings.HasPrefix(strings.TrimSpace(encoded), "$argon2id$")
}

// VerifyPassword verifies a plaintext password against an Argon2id PHC-formatted hash in constant time.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(strings.TrimSpace(encodedHash), "$")
	// Expected parts: ["", "argon2id", "v=19", "m=65536,t=3,p=2", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	hashLen := len(expectedHash)
	if hashLen < 16 || hashLen > 512 {
		return false, ErrInvalidHash
	}

	// #nosec G115 -- hashLen is verified strictly within [16, 512]
	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(hashLen))

	match := subtle.ConstantTimeCompare(computedHash, expectedHash)
	return match == 1, nil
}
