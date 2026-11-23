package authn_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

func TestPasswordReset_ResetsPasswordOnce(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	ctx := context.Background()

	token, user, ok, err := f.svc.RequestPasswordReset(ctx, f.tenant, "alice@example.com")
	if err != nil || !ok || user.ID != u.ID || token == "" {
		t.Fatalf("RequestPasswordReset = %q, %v, %v, %v", token, user.ID, ok, err)
	}
	if err := f.svc.ResetPassword(ctx, f.tenant, token, "a brand new password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if _, err := f.svc.VerifyPassword(ctx, f.tenant, "alice", "a brand new password"); err != nil {
		t.Fatalf("new password must work: %v", err)
	}
	if err := f.svc.ResetPassword(ctx, f.tenant, token, "yet another password"); !errors.Is(err, authn.ErrInvalidToken) {
		t.Fatalf("token reuse: err = %v", err)
	}
}

func TestPasswordReset_UnknownUserIsNotAnError(t *testing.T) {
	f := setup(t, identity.Settings{})
	_, _, ok, err := f.svc.RequestPasswordReset(context.Background(), f.tenant, "nobody@example.com")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v; want false, nil (caller responds the same either way)", ok, err)
	}
}

func TestPasswordReset_TokenExpires(t *testing.T) {
	f := setup(t, identity.Settings{})
	f.user(t, "alice", pw)
	ctx := context.Background()
	token, _, _, _ := f.svc.RequestPasswordReset(ctx, f.tenant, "alice")

	f.clock.Advance(31 * time.Minute)
	if err := f.svc.ResetPassword(ctx, f.tenant, token, "a brand new password"); !errors.Is(err, authn.ErrInvalidToken) {
		t.Fatalf("expired token: err = %v", err)
	}
}

func TestEmailVerification(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	ctx := context.Background()

	token, err := f.svc.IssueEmailVerification(ctx, f.tenant, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.VerifyEmail(ctx, f.tenant, token); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	got, _ := f.ids.GetUser(ctx, f.tenant.ID, u.ID)
	if !got.EmailVerified {
		t.Fatal("email must be verified")
	}
	if err := f.svc.VerifyEmail(ctx, f.tenant, token); !errors.Is(err, authn.ErrInvalidToken) {
		t.Fatalf("token reuse: err = %v", err)
	}
}

func TestPasswordResetTokenCannotVerifyEmail(t *testing.T) {
	f := setup(t, identity.Settings{})
	f.user(t, "alice", pw)
	token, _, _, _ := f.svc.RequestPasswordReset(context.Background(), f.tenant, "alice")
	if err := f.svc.VerifyEmail(context.Background(), f.tenant, token); !errors.Is(err, authn.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestHIBP_SendsOnlyHashPrefix(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"))
	}))
	defer srv.Close()
	c := authn.NewHIBPClient(srv.URL, srv.Client())

	breached, err := c.IsBreached(context.Background(), "password")
	if err != nil || !breached {
		t.Fatalf("breached=%v err=%v", breached, err)
	}
	if gotPath != "/range/5BAA6" {
		t.Fatalf("only the 5-char prefix may be sent, got path %q", gotPath)
	}
	if breached, _ := c.IsBreached(context.Background(), "a long unique passphrase"); breached {
		t.Fatal("unknown password must not be reported as breached")
	}
}

func TestSetPassword_RejectsBreachedWhenEnabled(t *testing.T) {
	f := setup(t, identity.Settings{PasswordBreachCheck: true})
	u := f.user(t, "alice", "")
	svc := authn.NewService(pgtestPool(t), authn.NewPasswordHasher(fastParams), authn.WithBreachChecker(alwaysBreached{}))
	if err := svc.SetPassword(context.Background(), f.tenant, u.ID, "breached but long"); !errors.Is(err, authn.ErrBreachedPassword) {
		t.Fatalf("err = %v", err)
	}
}

type alwaysBreached struct{}

func (alwaysBreached) IsBreached(context.Context, string) (bool, error) { return true, nil }
