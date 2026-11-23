// Package e2e tests IdaaS end to end over HTTPS with real RP libraries.
// These tests are the executable requirements of the system.
package e2e

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/app"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
)

type mailbox struct {
	mu   sync.Mutex
	msgs []mail
}

type mail struct{ to, subject, body string }

func (m *mailbox) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, mail{to, subject, body})
	return nil
}

func (m *mailbox) last(t *testing.T, to string) mail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.msgs) - 1; i >= 0; i-- {
		if m.msgs[i].to == to {
			return m.msgs[i]
		}
	}
	t.Fatalf("no mail to %s", to)
	return mail{}
}

var linkRe = regexp.MustCompile(`https://\S+`)

func (m mail) link() string { return linkRe.FindString(m.body) }

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	app    *app.App
	base   string
	mail   *mailbox
	tenant identity.Tenant
	hc     *http.Client
}

const password = "correct horse battery staple"

func newHarness(t *testing.T, settings identity.Settings) *harness {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// Serve as https://example.com:<port> (the test certificate's name) so
	// cookies and WebAuthn see a real domain; dial it to the test listener.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	base := "https://example.com:" + port
	tr := srv.Client().Transport.(*http.Transport).Clone()
	dialer := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, _ := net.SplitHostPort(addr); host == "example.com" {
			addr = srv.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{Transport: tr}
	mb := &mailbox{}
	a, err := app.New(app.Config{
		Pool:           pgtest.Pool(t),
		BaseURL:        base,
		EncryptionKeys: map[string][]byte{"test": make([]byte, 32)},
		ActiveKeyID:    "test",
		PasswordParams: &authn.Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		Mailer:         mb,
		HTTPClient:     client,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = a.Handler()
	h := &harness{t: t, srv: srv, app: a, base: base, mail: mb, hc: client}
	h.tenant, err = a.Identity().CreateTenantWithSettings(context.Background(), "t-"+uuid.NewString()[:12], "Test", settings)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) issuer() string { return h.base + "/t/" + h.tenant.Slug }

func (h *harness) httpClient() *http.Client { return h.hc }

func (h *harness) user(loginID string) identity.User {
	h.t.Helper()
	u, err := h.app.Identity().CreateUser(context.Background(), h.tenant.ID, identity.NewUser{
		LoginID: loginID, Email: loginID + "@example.com", EmailVerified: true, GivenName: "Test", FamilyName: loginID,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.app.Authn().SetPassword(context.Background(), h.tenant, u.ID, password); err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) client(nc oidc.NewClient) (oidc.Client, string) {
	h.t.Helper()
	if nc.Name == "" {
		nc.Name = "rp"
	}
	if nc.Type == "" {
		nc.Type = oidc.Confidential
	}
	if nc.GrantTypes == nil {
		nc.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if nc.AllowedScopes == nil {
		nc.AllowedScopes = []string{"openid", "profile", "email", "offline_access"}
	}
	c, s, err := h.app.Clients().Create(context.Background(), h.tenant.ID, nc)
	if err != nil {
		h.t.Fatal(err)
	}
	return c, s
}

// waitMail waits briefly for an asynchronously sent mail.
func waitMail(t *testing.T, h *harness, to string) mail {
	t.Helper()
	for range 50 {
		h.mail.mu.Lock()
		n := len(h.mail.msgs)
		h.mail.mu.Unlock()
		for i := n - 1; i >= 0; i-- {
			h.mail.mu.Lock()
			m := h.mail.msgs[i]
			h.mail.mu.Unlock()
			if m.to == to {
				return m
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no mail to %s", to)
	return mail{}
}
