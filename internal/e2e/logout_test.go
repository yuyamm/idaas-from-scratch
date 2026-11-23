package e2e

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

// Requirement: RP-Initiated Logout ends the IdP session, redirects only to a
// registered post_logout_redirect_uri and notifies RPs via Back-Channel Logout.
func TestE2E_RPInitiatedAndBackChannelLogout(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	logoutTokens := make(chan string, 1)
	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		logoutTokens <- r.PostForm.Get("logout_token")
	}))
	defer rpServer.Close()
	bc := rpServer.URL + "/backchannel"
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true,
		PostLogoutRedirectURIs: []string{"https://rp.example/bye"}, BackchannelLogoutURI: &bc})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback, "https://rp.example/bye")

	p, verifier, _ := r.authorize(b)
	res := r.finish(t, passwordLogin(b, p, "alice"), verifier)

	q := url.Values{"id_token_hint": {res.raw}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s1"}}
	p = b.get(h.issuer() + "/logout?" + q.Encode())
	if p.location != "https://rp.example/bye?state=s1" {
		t.Fatalf("logout redirect = %q (status %d)", p.location, p.status)
	}
	select {
	case tok := <-logoutTokens:
		if tok == "" {
			t.Fatal("empty logout_token")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no back-channel logout")
	}

	// The IdP session is gone: authorizing again shows the login page.
	p, _, _ = r.authorize(b)
	if !strings.Contains(p.url.Path, "/login") {
		t.Fatalf("expected login page after logout, got %s", p.url)
	}

	// Unregistered post-logout redirect URIs are not followed.
	p = b.get(h.issuer() + "/logout?" + url.Values{"id_token_hint": {res.raw}, "post_logout_redirect_uri": {"https://evil.example/"}}.Encode())
	if p.location != "" || p.status != http.StatusOK {
		t.Fatalf("redirected to unregistered URI: %q", p.location)
	}
}
