package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

func postForm(t *testing.T, c *http.Client, endpoint, user, pass string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// Requirement: M2M clients get access tokens with client credentials; resource
// servers validate opaque tokens with introspection; clients revoke tokens.
func TestE2E_ClientCredentialsIntrospectionRevocation(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	m2m, m2mSecret := h.client(oidc.NewClient{GrantTypes: []string{"client_credentials"}, AllowedScopes: []string{"orders:read"}, AccessTokenFormat: "opaque"})
	rs, rsSecret := h.client(oidc.NewClient{GrantTypes: []string{"client_credentials"}})

	cfg := clientcredentials.Config{ClientID: m2m.ClientID, ClientSecret: m2mSecret, TokenURL: h.issuer() + "/token", Scopes: []string{"orders:read"}}
	tok, err := cfg.Token(context.WithValue(context.Background(), oauth2HTTPClient, h.httpClient()))
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}

	status, intro := postForm(t, h.httpClient(), h.issuer()+"/introspect", rs.ClientID, rsSecret, url.Values{"token": {tok.AccessToken}})
	if status != 200 || intro["active"] != true || intro["client_id"] != m2m.ClientID || intro["scope"] != "orders:read" {
		t.Fatalf("introspect = %d %v", status, intro)
	}

	status, _ = postForm(t, h.httpClient(), h.issuer()+"/revoke", m2m.ClientID, m2mSecret, url.Values{"token": {tok.AccessToken}})
	if status != 200 {
		t.Fatalf("revoke status = %d", status)
	}
	_, intro = postForm(t, h.httpClient(), h.issuer()+"/introspect", rs.ClientID, rsSecret, url.Values{"token": {tok.AccessToken}})
	if intro["active"] != false {
		t.Fatalf("revoked token still active: %v", intro)
	}
}

// Requirement: client authentication failures return 401 invalid_client.
func TestE2E_TokenEndpointRejectsBadClientSecret(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	m2m, _ := h.client(oidc.NewClient{GrantTypes: []string{"client_credentials"}})
	status, body := postForm(t, h.httpClient(), h.issuer()+"/token", m2m.ClientID, "wrong", url.Values{"grant_type": {"client_credentials"}})
	if status != 401 || body["error"] != "invalid_client" {
		t.Fatalf("got %d %v", status, body)
	}
}

// Requirement: tokens of one tenant are useless at another tenant.
func TestE2E_TenantIsolation(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(b)
	res := r.finish(t, passwordLogin(b, p, "alice"), verifier)

	other, err := h.app.Identity().CreateTenant(context.Background(), "o-"+h.tenant.Slug, "Other")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, h.base+"/t/"+other.Slug+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+res.token.AccessToken)
	resp, err := h.httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo at another tenant: status %d", resp.StatusCode)
	}

	// The other tenant's login does not know alice.
	b2 := newBrowser(t, h.httpClient())
	p = passwordLogin(b2, b2.get(h.base+"/t/"+other.Slug+"/login"), "alice")
	if p.status != http.StatusUnauthorized {
		t.Fatalf("cross-tenant login: status %d", p.status)
	}
}

var oauth2HTTPClient = oauth2.HTTPClient
