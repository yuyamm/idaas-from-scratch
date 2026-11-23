package crypto

import (
	"bytes"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestAESGCM_RoundTrip(t *testing.T) {
	e, err := NewAESGCM("k1", map[string][]byte{"k1": key(1)})
	if err != nil {
		t.Fatal(err)
	}
	ct, keyID, err := e.Encrypt([]byte("seed"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "k1" || bytes.Contains(ct, []byte("seed")) {
		t.Fatalf("keyID=%s ct=%x", keyID, ct)
	}
	pt, err := e.Decrypt(ct, keyID, []byte("aad"))
	if err != nil || string(pt) != "seed" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
}

func TestAESGCM_RejectsWrongAAD(t *testing.T) {
	e, _ := NewAESGCM("k1", map[string][]byte{"k1": key(1)})
	ct, keyID, _ := e.Encrypt([]byte("seed"), []byte("tenant-a"))
	if _, err := e.Decrypt(ct, keyID, []byte("tenant-b")); err == nil {
		t.Fatal("ciphertext bound to one context must not decrypt in another")
	}
}

func TestAESGCM_DecryptsWithRetiredKeyAfterRotation(t *testing.T) {
	old, _ := NewAESGCM("k1", map[string][]byte{"k1": key(1)})
	ct, keyID, _ := old.Encrypt([]byte("seed"), nil)

	rotated, _ := NewAESGCM("k2", map[string][]byte{"k1": key(1), "k2": key(2)})
	if _, id, _ := rotated.Encrypt([]byte("x"), nil); id != "k2" {
		t.Fatalf("new encryptions must use the active key, got %s", id)
	}
	if pt, err := rotated.Decrypt(ct, keyID, nil); err != nil || string(pt) != "seed" {
		t.Fatalf("old ciphertext must still decrypt: %q, %v", pt, err)
	}
}

func TestNewAESGCM_RejectsBadConfig(t *testing.T) {
	if _, err := NewAESGCM("k1", map[string][]byte{"k1": []byte("short")}); err == nil {
		t.Fatal("want error for non-256-bit key")
	}
	if _, err := NewAESGCM("missing", map[string][]byte{"k1": key(1)}); err == nil {
		t.Fatal("want error when active key is missing")
	}
}
