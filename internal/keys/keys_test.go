package keys_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/keys"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

func setup(t *testing.T) (*keys.Service, identity.Tenant, *clock) {
	t.Helper()
	enc, _ := crypto.NewAESGCM("k", map[string][]byte{"k": make([]byte, 32)})
	c := &clock{t: time.Now().UTC()}
	return keys.NewService(pgtest.Pool(t), enc, keys.WithClock(c.Now)), testutil.NewTenant(t, identity.Settings{}), c
}

func kids(s jose.JSONWebKeySet) map[string]bool {
	m := map[string]bool{}
	for _, k := range s.Keys {
		m[k.KeyID] = true
	}
	return m
}

func verify(t *testing.T, token string, set jose.JSONWebKeySet) error {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return err
	}
	keysForKid := set.Key(parsed.Headers[0].KeyID)
	if len(keysForKid) == 0 {
		return jose.ErrJWKSKidNotFound
	}
	var claims map[string]any
	return parsed.Claims(keysForKid[0].Key, &claims)
}

func TestJWKS_PublishesCurrentAndNextKeys(t *testing.T) {
	svc, tn, _ := setup(t)
	ctx := context.Background()

	set, err := svc.JWKS(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("want current + next keys, got %d", len(set.Keys))
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || k.Use != "sig" || k.Algorithm != "RS256" || k.KeyID == "" {
			t.Fatalf("bad JWK: %+v", k)
		}
	}
}

func TestSign_VerifiesWithJWKS(t *testing.T) {
	svc, tn, _ := setup(t)
	ctx := context.Background()

	token, err := svc.SignJWT(ctx, tn.ID, "JWT", map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := svc.JWKS(ctx, tn.ID)
	if err := verify(t, token, set); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRotate_OldTokensStillVerify(t *testing.T) {
	svc, tn, _ := setup(t)
	ctx := context.Background()
	before, _ := svc.JWKS(ctx, tn.ID)
	token, _ := svc.SignJWT(ctx, tn.ID, "JWT", map[string]any{"sub": "u1"})

	if err := svc.Rotate(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := svc.JWKS(ctx, tn.ID)
	if len(after.Keys) != 3 {
		t.Fatalf("want next + current + retiring after rotation, got %d", len(after.Keys))
	}
	for kid := range kids(before) {
		if !kids(after)[kid] {
			t.Fatalf("key %s disappeared from JWKS right after rotation", kid)
		}
	}
	if err := verify(t, token, after); err != nil {
		t.Fatalf("token signed before rotation must verify: %v", err)
	}
	newToken, _ := svc.SignJWT(ctx, tn.ID, "JWT", map[string]any{"sub": "u1"})
	p1, _ := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	p2, _ := jwt.ParseSigned(newToken, []jose.SignatureAlgorithm{jose.RS256})
	if p1.Headers[0].KeyID == p2.Headers[0].KeyID {
		t.Fatal("new tokens must be signed with the promoted key")
	}
}

func TestRetire_RemovesRetiringKeysAfterMaxTokenLifetime(t *testing.T) {
	svc, tn, c := setup(t)
	ctx := context.Background()
	svc.JWKS(ctx, tn.ID)
	svc.Rotate(ctx, tn.ID)

	if err := svc.RetireExpired(ctx, tn.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if set, _ := svc.JWKS(ctx, tn.ID); len(set.Keys) != 3 {
		t.Fatalf("retiring key must stay until tokens expire, got %d keys", len(set.Keys))
	}
	c.t = c.t.Add(time.Hour + time.Second)
	svc.RetireExpired(ctx, tn.ID, time.Hour)
	if set, _ := svc.JWKS(ctx, tn.ID); len(set.Keys) != 2 {
		t.Fatalf("retired key must leave JWKS, got %d keys", len(set.Keys))
	}
}

func TestJWKS_IsPerTenant(t *testing.T) {
	svc, a, _ := setup(t)
	b := testutil.NewTenant(t, identity.Settings{})
	ctx := context.Background()
	ka, _ := svc.JWKS(ctx, a.ID)
	kb, _ := svc.JWKS(ctx, b.ID)
	for kid := range kids(ka) {
		if kids(kb)[kid] {
			t.Fatal("tenants must not share signing keys")
		}
	}
}
