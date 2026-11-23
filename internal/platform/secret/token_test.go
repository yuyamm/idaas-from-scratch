package secret

import "testing"

func TestNewToken_IsRandomAndURLSafe(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b {
		t.Fatal("tokens must be random")
	}
	if len(a) < 43 { // 32 bytes base64url without padding
		t.Fatalf("token too short: %q", a)
	}
	for _, c := range a {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			t.Fatalf("token is not URL-safe: %q", a)
		}
	}
}

func TestHashToken_IsDeterministicAndHidesInput(t *testing.T) {
	if HashToken("abc") != HashToken("abc") {
		t.Fatal("hash must be deterministic")
	}
	if HashToken("abc") == "abc" || HashToken("abc") == HashToken("abd") {
		t.Fatal("hash must differ from input and across inputs")
	}
}
