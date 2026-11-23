package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/federation"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

// externalIdP makes another tenant of the same server act as an external
// OIDC IdP (like Google) for h.tenant.
func externalIdP(t *testing.T, h *harness, allowSignup bool) (identity.Tenant, federation.IdentityProvider) {
	t.Helper()
	ctx := context.Background()
	ext, err := h.app.Identity().CreateTenant(ctx, "ext-"+uuid.NewString()[:8], "External IdP")
	if err != nil {
		t.Fatal(err)
	}
	c, secret, err := h.app.Clients().Create(ctx, ext.ID, oidc.NewClient{Name: "idaas", Type: oidc.Confidential, FirstParty: true,
		GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{h.issuer() + "/federation/callback"},
		AllowedScopes: []string{"openid", "email", "profile"}})
	if err != nil {
		t.Fatal(err)
	}
	idp, err := h.app.Federation().CreateIdP(ctx, h.tenant.ID, federation.IdentityProviderInput{
		Name: "ExternalCorp", Issuer: h.base + "/t/" + ext.Slug, ClientID: c.ClientID, ClientSecret: &secret, AllowSignup: allowSignup})
	if err != nil {
		t.Fatal(err)
	}
	return ext, idp
}

func externalUser(t *testing.T, h *harness, ext identity.Tenant, loginID, email string) {
	t.Helper()
	u, err := h.app.Identity().CreateUser(context.Background(), ext.ID, identity.NewUser{LoginID: loginID, Email: email, EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	h.app.Authn().SetPassword(context.Background(), ext, u.ID, password)
}

// Requirement: users log in with an external OIDC IdP; with sign-up allowed a
// new local account is created and linked.
func TestE2E_ExternalIdPLoginCreatesAccount(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	ext, _ := externalIdP(t, h, true)
	externalUser(t, h, ext, "dave", "dave@external.example")
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)

	p, verifier, _ := r.authorize(b)
	p = b.submit(p, "/federation/", nil) // "ExternalCorp でログイン"
	p = passwordLogin(b, p, "dave")      // at the external IdP
	res := r.finish(t, p, verifier)      // back at the RP
	var claims struct {
		Email string   `json:"email"`
		AMR   []string `json:"amr"`
	}
	res.idToken.Claims(&claims)
	if claims.Email != "dave@external.example" || strings.Join(claims.AMR, ",") != "fed" {
		t.Fatalf("claims = %+v", claims)
	}
	local, err := h.app.Identity().FindUserByEmail(context.Background(), h.tenant.ID, "dave@external.example")
	if err != nil || res.idToken.Subject != local.ID.String() {
		t.Fatalf("local account: %+v, %v", local, err)
	}
}

// Requirement: a matching email alone never merges accounts; the user links
// explicitly after signing in to the existing account.
func TestE2E_ExternalIdPRequiresExplicitLinking(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	ext, _ := externalIdP(t, h, true)
	existing := h.user("erin")
	externalUser(t, h, ext, "erin-ext", "erin@example.com") // same email as the local account
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)

	b := newBrowser(t, h.httpClient(), rpCallback)
	p, _, _ := r.authorize(b)
	p = passwordLogin(b, b.submit(p, "/federation/", nil), "erin-ext")
	if !strings.Contains(p.body, "既存のアカウント") || p.location != "" {
		t.Fatalf("must not auto-merge (status %d, location %q):\n%s", p.status, p.location, p.body)
	}

	// Sign in to the local account and link explicitly from the account page.
	b2 := newBrowser(t, h.httpClient(), rpCallback)
	acct := passwordLogin(b2, b2.get(h.issuer()+"/account"), "erin")
	p = b2.submit(acct, "/link", nil)
	p = passwordLogin(b2, p, "erin-ext")
	if !strings.Contains(p.body, "外部アカウントを連携しました") {
		t.Fatalf("linking failed:\n%s", p.body)
	}

	// Now the external login maps to the existing account.
	b3 := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(b3)
	res := r.finish(t, passwordLogin(b3, b3.submit(p, "/federation/", nil), "erin-ext"), verifier)
	if res.idToken.Subject != existing.ID.String() {
		t.Fatalf("sub = %s, want existing account %s", res.idToken.Subject, existing.ID)
	}
}

// Requirement: without sign-up, unknown external users are rejected.
func TestE2E_ExternalIdPWithoutSignup(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	ext, _ := externalIdP(t, h, false)
	externalUser(t, h, ext, "frank", "frank@external.example")
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, _, _ := r.authorize(b)
	p = passwordLogin(b, b.submit(p, "/federation/", nil), "frank")
	if !strings.Contains(p.body, "アカウントが見つかりません") {
		t.Fatalf("unexpected page:\n%s", p.body)
	}
}
