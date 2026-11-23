package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

const rpCallback = "https://rp.example/callback"

type rp struct {
	cfg      oauth2.Config
	verifier *gooidc.IDTokenVerifier
	provider *gooidc.Provider
	ctx      context.Context
}

func newRP(t *testing.T, h *harness, c oidc.Client, secret string, scopes ...string) rp {
	t.Helper()
	ctx := gooidc.ClientContext(context.Background(), h.httpClient())
	provider, err := gooidc.NewProvider(ctx, h.issuer())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "profile", "email"}
	}
	return rp{
		cfg: oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(),
			RedirectURL: rpCallback, Scopes: scopes},
		verifier: provider.Verifier(&gooidc.Config{ClientID: c.ClientID}),
		provider: provider,
		ctx:      ctx,
	}
}

type loginResult struct {
	token   *oauth2.Token
	idToken *gooidc.IDToken
	raw     string
}

// authorize starts the code flow and returns the browser's first page.
func (r rp) authorize(b *browser, extra ...oauth2.AuthCodeOption) (*page, string, string) {
	verifier := oauth2.GenerateVerifier()
	opts := append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce("nonce-1")}, extra...)
	return b.get(r.cfg.AuthCodeURL("state-1", opts...)), verifier, "state-1"
}

func (r rp) finish(t *testing.T, p *page, verifier string) loginResult {
	t.Helper()
	if p.location == "" || !strings.HasPrefix(p.location, rpCallback) {
		t.Fatalf("expected redirect to RP, got status %d at %s:\n%s", p.status, p.url, p.body)
	}
	cb, _ := url.Parse(p.location)
	q := cb.Query()
	if q.Get("error") != "" {
		t.Fatalf("authorization error: %s %s", q.Get("error"), q.Get("error_description"))
	}
	if q.Get("state") != "state-1" {
		t.Fatalf("state = %q", q.Get("state"))
	}
	tok, err := r.cfg.Exchange(r.ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := r.verifier.Verify(r.ctx, raw)
	if err != nil {
		t.Fatalf("ID token verification: %v", err)
	}
	if idt.Nonce != "nonce-1" {
		t.Fatalf("nonce = %q", idt.Nonce)
	}
	return loginResult{token: tok, idToken: idt, raw: raw}
}

func passwordLogin(b *browser, p *page, loginID string) *page {
	return b.submit(p, "/login", map[string]string{"login_id": loginID, "password": password})
}

// Requirement: an RP can log a user in with Authorization Code + PKCE and get
// verified ID token claims, userinfo and refreshed tokens.
func TestE2E_PasswordLoginWithCodeFlow(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	u := h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret, gooidc.ScopeOpenID, "profile", "email", gooidc.ScopeOfflineAccess)
	b := newBrowser(t, h.httpClient(), rpCallback)

	p, verifier, _ := r.authorize(b)
	if !strings.Contains(p.url.Path, "/login") {
		t.Fatalf("expected login page, got %s", p.url)
	}
	res := r.finish(t, passwordLogin(b, p, "alice"), verifier)

	if res.idToken.Subject != u.ID.String() || res.idToken.Issuer != h.issuer() {
		t.Fatalf("id token sub=%s iss=%s", res.idToken.Subject, res.idToken.Issuer)
	}
	var claims struct {
		Email string   `json:"email"`
		AMR   []string `json:"amr"`
		ACR   string   `json:"acr"`
	}
	res.idToken.Claims(&claims)
	if claims.Email != "alice@example.com" || len(claims.AMR) != 1 || claims.AMR[0] != "pwd" {
		t.Fatalf("claims = %+v", claims)
	}

	info, err := r.provider.UserInfo(r.ctx, oauth2.StaticTokenSource(res.token))
	if err != nil || info.Subject != u.ID.String() || info.Email != "alice@example.com" {
		t.Fatalf("userinfo = %+v, %v", info, err)
	}

	refreshed, err := r.cfg.TokenSource(r.ctx, &oauth2.Token{RefreshToken: res.token.RefreshToken}).Token()
	if err != nil || refreshed.AccessToken == res.token.AccessToken || refreshed.RefreshToken == res.token.RefreshToken {
		t.Fatalf("refresh: %v", err)
	}

	// Single sign-on: a second authorization reuses the IdP session.
	p2, verifier2, _ := r.authorize(b)
	r.finish(t, p2, verifier2)
}

// Requirement: wrong passwords and unknown users get the same response.
func TestE2E_LoginFailureDoesNotRevealAccountExistence(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)

	b := newBrowser(t, h.httpClient(), rpCallback)
	p, _, _ := r.authorize(b)
	wrong := b.submit(p, "/login", map[string]string{"login_id": "alice", "password": "wrong password!!"})
	p, _, _ = r.authorize(b)
	unknown := b.submit(p, "/login", map[string]string{"login_id": "nobody", "password": password})
	if wrong.status != unknown.status || !strings.Contains(wrong.body, "ログイン ID またはパスワードが正しくありません") ||
		!strings.Contains(unknown.body, "ログイン ID またはパスワードが正しくありません") {
		t.Fatalf("responses differ:\nwrong(%d): %s\nunknown(%d): %s", wrong.status, wrong.body, unknown.status, unknown.body)
	}
}

// Requirement: session cookies are Secure, HttpOnly and SameSite.
func TestE2E_SessionCookieAttributes(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, _, _ := r.authorize(b)

	var setCookie string
	b.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, c := range req.Response.Header.Values("Set-Cookie") {
			if strings.HasPrefix(c, "idaas_session=") {
				setCookie = c
			}
		}
		if strings.HasPrefix(req.URL.String(), rpCallback) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	passwordLogin(b, p, "alice")
	for _, attr := range []string{"Secure", "HttpOnly", "SameSite=Lax", "Path=/t/" + h.tenant.Slug} {
		if !strings.Contains(setCookie, attr) {
			t.Fatalf("session cookie %q lacks %s", setCookie, attr)
		}
	}
}

// Requirement: third-party clients ask for consent once.
func TestE2E_ConsentForThirdPartyClient(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)

	p, verifier, _ := r.authorize(b)
	p = passwordLogin(b, p, "alice")
	if !strings.Contains(p.url.Path, "/consent") {
		t.Fatalf("expected consent page, got %s", p.url)
	}
	r.finish(t, b.submit(p, "/consent", map[string]string{"decision": "allow"}), verifier)

	p, verifier, _ = r.authorize(b)
	r.finish(t, p, verifier) // remembered
}

// Requirement: denying consent returns access_denied to the RP.
func TestE2E_ConsentDenied(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)

	p, _, _ := r.authorize(b)
	p = b.submit(passwordLogin(b, p, "alice"), "/consent", map[string]string{"decision": "deny"})
	if !strings.Contains(p.location, "error=access_denied") {
		t.Fatalf("location = %s", p.location)
	}
}

// Requirement: unregistered redirect URIs are never redirected to.
func TestE2E_UnregisteredRedirectURIShowsErrorPage(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}})
	r := newRP(t, h, c, secret)
	r.cfg.RedirectURL = "https://evil.example/callback"
	b := newBrowser(t, h.httpClient(), rpCallback, "https://evil.example")
	p, _, _ := r.authorize(b)
	if p.status != http.StatusBadRequest || p.location != "" {
		t.Fatalf("status=%d location=%q", p.status, p.location)
	}
}

// Requirement: prompt=none without a session returns login_required.
func TestE2E_PromptNoneWithoutSession(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, _, _ := r.authorize(b, oauth2.SetAuthURLParam("prompt", "none"))
	if !strings.Contains(p.location, "error=login_required") {
		t.Fatalf("location = %s", p.location)
	}
}

func oidcClientForRP() oidc.NewClient {
	return oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true}
}
