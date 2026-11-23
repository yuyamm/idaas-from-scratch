package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

// Requirement: users reset forgotten passwords by email; the response does not
// reveal whether the account exists; the reset revokes existing sessions.
func TestE2E_PasswordReset(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidc.NewClient{RedirectURIs: []string{rpCallback}, FirstParty: true})
	r := newRP(t, h, c, secret)

	// An existing session that must be revoked by the reset.
	old := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(old)
	r.finish(t, passwordLogin(old, p, "alice"), verifier)

	b := newBrowser(t, h.httpClient())
	forgot := b.get(h.issuer() + "/forgot")
	known := b.submit(forgot, "/forgot", map[string]string{"login_id": "alice@example.com"})
	unknown := b.submit(b.get(h.issuer()+"/forgot"), "/forgot", map[string]string{"login_id": "nobody@example.com"})
	if known.body != unknown.body {
		t.Fatal("responses for existing and unknown accounts differ")
	}

	link := waitMail(t, h, "alice@example.com").link()
	p = b.submit(b.get(link), "/reset", map[string]string{"password": "a whole new password"})
	if !strings.Contains(p.body, "パスワードを変更しました") {
		t.Fatalf("reset failed:\n%s", p.body)
	}
	if again := b.submit(b.get(link), "/reset", map[string]string{"password": "yet another password"}); !strings.Contains(again.body, "リンクが無効です") {
		t.Fatal("reset link must be single-use")
	}

	p, _, _ = r.authorize(old)
	if !strings.Contains(p.url.Path, "/login") {
		t.Fatal("old session must be revoked after password reset")
	}
	_, err := h.app.Authn().VerifyPassword(context.Background(), h.tenant, "alice", "a whole new password")
	if err != nil {
		t.Fatalf("new password: %v", err)
	}
}

// Requirement: users verify their email address.
func TestE2E_EmailVerification(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	u, _ := h.app.Identity().CreateUser(context.Background(), h.tenant.ID, identity.NewUser{LoginID: "bob", Email: "bob@example.com"})
	h.app.Authn().SetPassword(context.Background(), h.tenant, u.ID, password)

	b := newBrowser(t, h.httpClient())
	p := b.get(h.issuer() + "/account")
	p = passwordLogin(b, p, "bob")
	if !strings.Contains(p.body, "未検証") {
		t.Fatalf("account page:\n%s", p.body)
	}
	b.submit(p, "/account/verify-email", nil)
	p = b.get(waitMail(t, h, "bob@example.com").link())
	if !strings.Contains(p.body, "確認しました") {
		t.Fatalf("verification failed:\n%s", p.body)
	}
	got, _ := h.app.Identity().GetUser(context.Background(), h.tenant.ID, u.ID)
	if !got.EmailVerified {
		t.Fatal("email_verified must be true")
	}
}
