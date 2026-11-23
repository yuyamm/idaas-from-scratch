// Package secret generates random tokens and hashes them for storage.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewToken returns 256 bits of randomness, base64url-encoded.
func NewToken() string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(32))
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secret: crypto/rand failed: " + err.Error())
	}
	return b
}

// HashToken returns the SHA-256 hex digest used to store high-entropy tokens.
// Plain SHA-256 is enough because the input is random, not a password.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
