package oidc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

func TestClients_ConfidentialClientAuthenticatesWithSecret(t *testing.T) {
	ctx := context.Background()
	cs := oidc.NewClientStore(pgtest.Pool(t))
	tn := testutil.NewTenant(t, identity.Settings{})

	c, secret, err := cs.Create(ctx, tn.ID, oidc.NewClient{
		Name: "app", Type: oidc.Confidential, AuthMethod: oidc.ClientSecretBasic,
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"https://app.example/cb"},
		AllowedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || c.ClientID == "" {
		t.Fatalf("client=%+v secret=%q", c, secret)
	}

	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: secret, Method: oidc.ClientSecretBasic}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: "wrong", Method: oidc.ClientSecretBasic}); !errors.Is(err, oidc.ErrClientAuth) {
		t.Fatalf("wrong secret: err = %v", err)
	}
	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Method: oidc.AuthNone}); !errors.Is(err, oidc.ErrClientAuth) {
		t.Fatalf("confidential client without secret: err = %v", err)
	}
	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: secret, Method: oidc.ClientSecretPost}); !errors.Is(err, oidc.ErrClientAuth) {
		t.Fatalf("auth method other than the registered one must be rejected: err = %v", err)
	}
}

func TestClients_PublicClientUsesNoSecret(t *testing.T) {
	ctx := context.Background()
	cs := oidc.NewClientStore(pgtest.Pool(t))
	tn := testutil.NewTenant(t, identity.Settings{})

	c, secret, err := cs.Create(ctx, tn.ID, oidc.NewClient{Name: "spa", Type: oidc.Public,
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"https://spa.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || c.AuthMethod != oidc.AuthNone {
		t.Fatalf("public client got secret=%q method=%s", secret, c.AuthMethod)
	}
	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Method: oidc.AuthNone}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestClients_SecretRotation(t *testing.T) {
	ctx := context.Background()
	cs := oidc.NewClientStore(pgtest.Pool(t))
	tn := testutil.NewTenant(t, identity.Settings{})
	c, s1, _ := cs.Create(ctx, tn.ID, oidc.NewClient{Name: "m2m", Type: oidc.Confidential, AuthMethod: oidc.ClientSecretBasic, GrantTypes: []string{"client_credentials"}})

	sec2, s2, err := cs.AddSecret(ctx, tn.ID, c.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{s1, s2} {
		if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: s, Method: oidc.ClientSecretBasic}); err != nil {
			t.Fatalf("both secrets must work during rotation: %v", err)
		}
	}
	secrets, _ := cs.ListSecrets(ctx, tn.ID, c.ID)
	for _, s := range secrets {
		if s.ID != sec2.ID {
			cs.DeleteSecret(ctx, tn.ID, c.ID, s.ID)
		}
	}
	if _, err := cs.Authenticate(ctx, tn.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: s1, Method: oidc.ClientSecretBasic}); !errors.Is(err, oidc.ErrClientAuth) {
		t.Fatalf("deleted secret must stop working: err = %v", err)
	}
}

func TestClients_InvisibleFromOtherTenant(t *testing.T) {
	ctx := context.Background()
	cs := oidc.NewClientStore(pgtest.Pool(t))
	a := testutil.NewTenant(t, identity.Settings{})
	b := testutil.NewTenant(t, identity.Settings{})
	c, s, _ := cs.Create(ctx, a.ID, oidc.NewClient{Name: "app", Type: oidc.Confidential, AuthMethod: oidc.ClientSecretBasic, GrantTypes: []string{"client_credentials"}})

	if _, err := cs.Authenticate(ctx, b.ID, oidc.ClientCredentials{ID: c.ClientID, Secret: s, Method: oidc.ClientSecretBasic}); !errors.Is(err, oidc.ErrClientAuth) {
		t.Fatalf("err = %v", err)
	}
}
