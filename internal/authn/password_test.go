package authn

import (
	"strings"
	"testing"
)

func TestPasswordHasher_HashThenVerify(t *testing.T) {
	h := NewPasswordHasher(DefaultArgon2Params)

	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("want PHC argon2id string, got %q", encoded)
	}

	ok, err := h.Verify("correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = h.Verify("wrong", encoded)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestPasswordHasher_HashIsSalted(t *testing.T) {
	h := NewPasswordHasher(DefaultArgon2Params)
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
}

func TestPasswordHasher_NeedsRehashWhenParamsChange(t *testing.T) {
	old := NewPasswordHasher(Argon2Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	encoded, _ := old.Hash("pw")

	if old.NeedsRehash(encoded) {
		t.Fatal("hash made with current params must not need rehash")
	}
	stronger := NewPasswordHasher(Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if !stronger.NeedsRehash(encoded) {
		t.Fatal("hash made with weaker params must need rehash")
	}
	// Old hashes must still verify after params change.
	if ok, _ := stronger.Verify("pw", encoded); !ok {
		t.Fatal("hash made with old params must still verify")
	}
}

func TestPasswordHasher_VerifyRejectsMalformed(t *testing.T) {
	h := NewPasswordHasher(DefaultArgon2Params)
	if _, err := h.Verify("pw", "not-a-phc-string"); err == nil {
		t.Fatal("want error for malformed hash")
	}
}
