package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

var secretRe = regexp.MustCompile(`キー：<code>([A-Z2-7]+)</code>`)
var recoveryRe = regexp.MustCompile(`<li class="recovery-code">([a-z2-7-]+)</li>`)

// enrollDuringLogin completes the forced TOTP enrollment and returns the
// secret and recovery codes.
func enrollDuringLogin(t *testing.T, b *browser, p *page) (string, []string, *page) {
	t.Helper()
	if !strings.Contains(p.url.Path, "/mfa/setup") {
		t.Fatalf("expected MFA setup, got %s:\n%s", p.url, p.body)
	}
	m := secretRe.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no TOTP secret on page:\n%s", p.body)
	}
	code, _ := totp.GenerateCode(m[1], time.Now())
	p = b.submit(p, "/mfa/setup", map[string]string{"code": code})
	var codes []string
	for _, c := range recoveryRe.FindAllStringSubmatch(p.body, -1) {
		codes = append(codes, c[1])
	}
	if len(codes) != 10 {
		t.Fatalf("want 10 recovery codes, got %d:\n%s", len(codes), p.body)
	}
	return m[1], codes, b.submit(p, "/mfa/continue", nil)
}

// Requirement: a tenant can require MFA; users enroll TOTP on first login and
// the ID token reports acr=mfa and amr=[pwd otp].
func TestE2E_MFARequiredEnrollsTOTPThenUsesIt(t *testing.T) {
	h := newHarness(t, identity.Settings{MFARequired: true})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)

	b := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(b)
	totpSecret, recovery, p := enrollDuringLogin(t, b, passwordLogin(b, p, "alice"))
	res := r.finish(t, p, verifier)
	var claims struct {
		ACR string   `json:"acr"`
		AMR []string `json:"amr"`
	}
	res.idToken.Claims(&claims)
	if claims.ACR != "urn:idaas:acr:mfa" || strings.Join(claims.AMR, ",") != "pwd,otp" {
		t.Fatalf("claims = %+v", claims)
	}

	// Next login in a fresh browser asks for the TOTP code.
	b2 := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ = r.authorize(b2)
	p = passwordLogin(b2, p, "alice")
	if !strings.HasSuffix(p.url.Path, "/mfa") {
		t.Fatalf("expected MFA prompt, got %s", p.url)
	}
	bad := b2.submit(p, "/mfa", map[string]string{"code": "000000"})
	if !strings.Contains(bad.body, "コードが正しくありません") {
		t.Fatalf("wrong code accepted:\n%s", bad.body)
	}
	time.Sleep(0) // codes are per 30s step; the enrollment step is already used
	code, _ := totp.GenerateCode(totpSecret, time.Now().Add(30*time.Second))
	r.finish(t, b2.submit(bad, "/mfa", map[string]string{"code": code}), verifier)

	// A recovery code works once.
	b3 := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ = r.authorize(b3)
	r.finish(t, b3.submit(passwordLogin(b3, p, "alice"), "/mfa", map[string]string{"code": recovery[0]}), verifier)
}

// Requirement: an RP can demand MFA with acr_values even when the tenant does
// not require it.
func TestE2E_RPRequestsMFAWithACRValues(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)

	// Password-only session first.
	p, verifier, _ := r.authorize(b)
	r.finish(t, passwordLogin(b, p, "alice"), verifier)

	// Step-up: the existing password session is not enough.
	p, verifier, _ = r.authorize(b, oauth2.SetAuthURLParam("acr_values", "urn:idaas:acr:mfa"))
	_, _, p = enrollDuringLogin(t, b, passwordLogin(b, p, "alice"))
	res := r.finish(t, p, verifier)
	var claims struct {
		ACR string `json:"acr"`
	}
	res.idToken.Claims(&claims)
	if claims.ACR != "urn:idaas:acr:mfa" {
		t.Fatalf("acr = %q", claims.ACR)
	}
}
