package authn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

// fastParams keeps tests quick; production uses DefaultArgon2Params.
var fastParams = authn.Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type fixture struct {
	svc    *authn.Service
	ids    *identity.Store
	tenant identity.Tenant
	clock  *clock
}

func setup(t *testing.T, st identity.Settings) fixture {
	t.Helper()
	pool := pgtest.Pool(t)
	c := &clock{t: time.Now().UTC().Truncate(time.Second)}
	enc, err := crypto.NewAESGCM("test", map[string][]byte{"test": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	svc := authn.NewService(pool, authn.NewPasswordHasher(fastParams), authn.WithClock(c.Now), authn.WithEncrypter(enc))
	return fixture{svc: svc, ids: identity.NewStore(pool), tenant: testutil.NewTenant(t, st), clock: c}
}

func (f fixture) user(t *testing.T, loginID, password string) identity.User {
	t.Helper()
	u, err := f.ids.CreateUser(context.Background(), f.tenant.ID, identity.NewUser{LoginID: loginID, Email: loginID + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if password != "" {
		if err := f.svc.SetPassword(context.Background(), f.tenant, u.ID, password); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

const pw = "correct horse battery"

func TestVerifyPassword_Succeeds(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)

	got, err := f.svc.VerifyPassword(context.Background(), f.tenant, "alice", pw)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("got user %v, want %v", got.ID, u.ID)
	}
}

func TestVerifyPassword_SameErrorForWrongPasswordAndUnknownUser(t *testing.T) {
	f := setup(t, identity.Settings{})
	f.user(t, "alice", pw)

	_, errWrong := f.svc.VerifyPassword(context.Background(), f.tenant, "alice", "wrong password!")
	_, errUnknown := f.svc.VerifyPassword(context.Background(), f.tenant, "nobody", pw)
	if !errors.Is(errWrong, authn.ErrInvalidCredentials) || !errors.Is(errUnknown, authn.ErrInvalidCredentials) {
		t.Fatalf("errWrong=%v errUnknown=%v; both must be ErrInvalidCredentials", errWrong, errUnknown)
	}
}

func TestVerifyPassword_LocksAfterThresholdEvenWithCorrectPassword(t *testing.T) {
	f := setup(t, identity.Settings{LockoutThreshold: 3, LockoutDurationSeconds: 600})
	f.user(t, "alice", pw)
	ctx := context.Background()

	for range 3 {
		f.svc.VerifyPassword(ctx, f.tenant, "alice", "wrong password!")
	}
	if _, err := f.svc.VerifyPassword(ctx, f.tenant, "alice", pw); !errors.Is(err, authn.ErrInvalidCredentials) {
		t.Fatalf("locked account accepted correct password: err=%v", err)
	}
	u, _ := f.ids.FindUserByLoginID(ctx, f.tenant.ID, "alice")
	if u.Status != identity.StatusLocked {
		t.Fatalf("status = %s, want locked", u.Status)
	}

	f.clock.Advance(601 * time.Second)
	if _, err := f.svc.VerifyPassword(ctx, f.tenant, "alice", pw); err != nil {
		t.Fatalf("after lock expiry: %v", err)
	}
	u, _ = f.ids.FindUserByLoginID(ctx, f.tenant.ID, "alice")
	if u.Status != identity.StatusActive || u.FailedLoginCount != 0 {
		t.Fatalf("after successful login: status=%s failed=%d", u.Status, u.FailedLoginCount)
	}
}

func TestVerifyPassword_RejectsDisabledUser(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	if err := f.ids.SetStatus(context.Background(), f.tenant.ID, u.ID, identity.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.VerifyPassword(context.Background(), f.tenant, "alice", pw); !errors.Is(err, authn.ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyPassword_RehashesWhenParamsChange(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	pool := pgtest.Pool(t)
	var before string
	pool.QueryRow(context.Background(), `SELECT password_hash FROM password_credentials WHERE user_id = $1`, u.ID).Scan(&before)

	stronger := authn.NewService(pool, authn.NewPasswordHasher(authn.Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}))
	if _, err := stronger.VerifyPassword(context.Background(), f.tenant, "alice", pw); err != nil {
		t.Fatal(err)
	}
	var after string
	pool.QueryRow(context.Background(), `SELECT password_hash FROM password_credentials WHERE user_id = $1`, u.ID).Scan(&after)
	if after == before {
		t.Fatal("password hash must be upgraded on login")
	}
}

func TestSetPassword_EnforcesMinimumLength(t *testing.T) {
	f := setup(t, identity.Settings{PasswordMinLength: 12})
	u := f.user(t, "alice", "")
	if err := f.svc.SetPassword(context.Background(), f.tenant, u.ID, "short"); !errors.Is(err, authn.ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

func TestSession_CreateThenLookup(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	ctx := context.Background()

	raw, s, err := f.svc.CreateSession(ctx, f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.LookupSession(ctx, f.tenant, raw)
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if got.ID != s.ID || got.UserID != u.ID {
		t.Fatalf("got %+v", got)
	}
	if _, err := f.svc.LookupSession(ctx, f.tenant, "not-a-session"); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("unknown session: err = %v", err)
	}
}

func TestSession_NotVisibleFromOtherTenant(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	other := testutil.NewTenant(t, identity.Settings{})
	raw, _, _ := f.svc.CreateSession(context.Background(), f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})

	if _, err := f.svc.LookupSession(context.Background(), other, raw); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
}

func TestSession_IdleTimeout(t *testing.T) {
	f := setup(t, identity.Settings{SessionIdleTimeoutSeconds: 60, SessionAbsoluteTimeoutSeconds: 3600})
	u := f.user(t, "alice", pw)
	ctx := context.Background()
	raw, _, _ := f.svc.CreateSession(ctx, f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})

	f.clock.Advance(50 * time.Second)
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw); err != nil {
		t.Fatalf("within idle timeout: %v", err)
	}
	f.clock.Advance(50 * time.Second) // 50s since last use: still fine
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw); err != nil {
		t.Fatalf("activity must extend idle timeout: %v", err)
	}
	f.clock.Advance(61 * time.Second)
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("after idle timeout: err = %v", err)
	}
}

func TestSession_AbsoluteTimeout(t *testing.T) {
	f := setup(t, identity.Settings{SessionIdleTimeoutSeconds: 60, SessionAbsoluteTimeoutSeconds: 100})
	u := f.user(t, "alice", pw)
	ctx := context.Background()
	raw, _, _ := f.svc.CreateSession(ctx, f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})

	for range 3 {
		f.clock.Advance(40 * time.Second)
		f.svc.LookupSession(ctx, f.tenant, raw)
	}
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("after absolute timeout: err = %v", err)
	}
}

func TestSession_RevokedByLogoutAndPasswordChange(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	ctx := context.Background()

	raw1, s1, _ := f.svc.CreateSession(ctx, f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})
	if err := f.svc.RevokeSession(ctx, f.tenant.ID, s1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw1); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("after logout: err = %v", err)
	}

	raw2, _, _ := f.svc.CreateSession(ctx, f.tenant, u.ID, authn.ACRPassword, []string{"pwd"})
	if err := f.svc.SetPassword(ctx, f.tenant, u.ID, "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.LookupSession(ctx, f.tenant, raw2); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("after password change: err = %v", err)
	}
}

func pgtestPool(t *testing.T) *pgxpool.Pool { return pgtest.Pool(t) }
