package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

func (b *browser) csrf(base string) string {
	u, _ := url.Parse(base)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == "idaas_csrf" {
			return c.Value
		}
	}
	b.t.Fatal("no CSRF cookie")
	return ""
}

func (b *browser) postJSON(rawURL, csrf, body string) (int, map[string]any, string) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	p := b.do(req)
	var m map[string]any
	json.Unmarshal([]byte(p.body), &m)
	return p.status, m, p.body
}

// Requirement: users register a passkey and log in with it (phishing
// resistant); the ID token reports amr=hwk and acr=mfa.
func TestE2E_PasskeyRegistrationAndLogin(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	u := h.user("alice")
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)
	origin, _ := url.Parse(h.base)
	rp := virtualwebauthn.RelyingParty{ID: origin.Hostname(), Name: "IdaaS", Origin: h.base}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: u.ID[:]})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register from the account page.
	b := newBrowser(t, h.httpClient())
	passwordLogin(b, b.get(h.issuer()+"/account"), "alice")
	b.get(h.issuer() + "/passkey/register")
	status, _, raw := b.postJSON(h.issuer()+"/passkey/register/begin", b.csrf(h.base), "")
	if status != 200 {
		t.Fatalf("register/begin = %d %s", status, raw)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(raw)
	if err != nil {
		t.Fatalf("parse attestation options: %v\n%s", err, raw)
	}
	att := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attOpts)
	status, res, raw := b.postJSON(h.issuer()+"/passkey/register/finish", b.csrf(h.base), att)
	if status != 200 || res["redirect"] == nil {
		t.Fatalf("register/finish = %d %s", status, raw)
	}
	authenticator.AddCredential(cred)

	// Log in with the passkey in a fresh browser during an RP authorization.
	b2 := newBrowser(t, h.httpClient(), rpCallback)
	login, verifier, _ := r.authorize(b2)
	returnTo := login.url.Query().Get("return_to")
	b2.get(h.issuer() + "/passkey/login?return_to=" + url.QueryEscape(returnTo))
	status, _, raw = b2.postJSON(h.issuer()+"/passkey/login/begin", b2.csrf(h.base), "")
	if status != 200 {
		t.Fatalf("login/begin = %d %s", status, raw)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(raw)
	if err != nil {
		t.Fatalf("parse assertion options: %v\n%s", err, raw)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertOpts)
	status, res, raw = b2.postJSON(h.issuer()+"/passkey/login/finish?return_to="+url.QueryEscape(returnTo), b2.csrf(h.base), assertion)
	if status != 200 {
		t.Fatalf("login/finish = %d %s", status, raw)
	}
	p := b2.get(h.base + res["redirect"].(string))
	result := r.finish(t, p, verifier)
	var claims struct {
		ACR string   `json:"acr"`
		AMR []string `json:"amr"`
	}
	result.idToken.Claims(&claims)
	if result.idToken.Subject != u.ID.String() || claims.ACR != "urn:idaas:acr:mfa" || strings.Join(claims.AMR, ",") != "hwk" {
		t.Fatalf("sub=%s claims=%+v", result.idToken.Subject, claims)
	}

	// A forged assertion (wrong key) is rejected.
	b3 := newBrowser(t, h.httpClient())
	b3.get(h.issuer() + "/passkey/login")
	_, _, raw = b3.postJSON(h.issuer()+"/passkey/login/begin", b3.csrf(h.base), "")
	assertOpts, _ = virtualwebauthn.ParseAssertionOptions(raw)
	forged := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	forged.ID = cred.ID
	status, _, _ = b3.postJSON(h.issuer()+"/passkey/login/finish", b3.csrf(h.base), virtualwebauthn.CreateAssertionResponse(rp, authenticator, forged, *assertOpts))
	if status != http.StatusUnauthorized {
		t.Fatalf("forged assertion: status %d", status)
	}
}
