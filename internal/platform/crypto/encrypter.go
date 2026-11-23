// Package crypto encrypts secrets at rest. Encrypter is the seam for swapping
// the local AES-GCM keyring for a KMS.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Encrypter encrypts secrets that must be recoverable (TOTP seeds, private
// keys, client secrets of external IdPs, webhook secrets).
type Encrypter interface {
	// Encrypt returns the ciphertext and the ID of the key used.
	Encrypt(plaintext, aad []byte) (ciphertext []byte, keyID string, err error)
	Decrypt(ciphertext []byte, keyID string, aad []byte) ([]byte, error)
}

// AESGCM is a local keyring of AES-256-GCM keys. New data is encrypted with
// the active key; retired keys stay available for decryption.
type AESGCM struct {
	active string
	aeads  map[string]cipher.AEAD
}

func NewAESGCM(active string, keys map[string][]byte) (*AESGCM, error) {
	e := &AESGCM{active: active, aeads: map[string]cipher.AEAD{}}
	for id, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("crypto: key %q must be 256 bits", id)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		e.aeads[id] = aead
	}
	if _, ok := e.aeads[active]; !ok {
		return nil, fmt.Errorf("crypto: active key %q not found", active)
	}
	return e, nil
}

func (e *AESGCM) Encrypt(plaintext, aad []byte) ([]byte, string, error) {
	aead := e.aeads[e.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), e.active, nil
}

var ErrDecrypt = errors.New("crypto: decryption failed")

func (e *AESGCM) Decrypt(ciphertext []byte, keyID string, aad []byte) ([]byte, error) {
	aead, ok := e.aeads[keyID]
	if !ok || len(ciphertext) < aead.NonceSize() {
		return nil, ErrDecrypt
	}
	n := aead.NonceSize()
	pt, err := aead.Open(nil, ciphertext[:n], ciphertext[n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
