package authn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func enrolled(t *testing.T, f fixture, u identity.User) (secret string, recovery []string) {
	t.Helper()
	ctx := context.Background()
	enr, err := f.svc.EnrollTOTP(ctx, f.tenant, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err = f.svc.ConfirmTOTP(ctx, f.tenant, u.ID, code(t, enr.Secret, f.clock.Now()))
	if err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	f.clock.Advance(30 * time.Second) // move past the step used for confirmation
	return enr.Secret, recovery
}

func TestTOTP_EnrollConfirmThenVerify(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	ctx := context.Background()

	if has, _ := f.svc.HasMFA(ctx, f.tenant.ID, u.ID); has {
		t.Fatal("no MFA before enrollment")
	}
	enr, err := f.svc.EnrollTOTP(ctx, f.tenant, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if enr.URL == "" || enr.Secret == "" {
		t.Fatalf("enrollment = %+v", enr)
	}
	if has, _ := f.svc.HasMFA(ctx, f.tenant.ID, u.ID); has {
		t.Fatal("unconfirmed TOTP must not count as MFA")
	}

	secret, recovery := enrolled(t, f, u)
	_ = enr
	if len(recovery) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(recovery))
	}
	if has, _ := f.svc.HasMFA(ctx, f.tenant.ID, u.ID); !has {
		t.Fatal("confirmed TOTP must count as MFA")
	}
	if err := f.svc.VerifyTOTP(ctx, f.tenant, u.ID, code(t, secret, f.clock.Now())); err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
}

func TestTOTP_RejectsWrongCode(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	enrolled(t, f, u)
	if err := f.svc.VerifyTOTP(context.Background(), f.tenant, u.ID, "000000"); !errors.Is(err, authn.ErrInvalidOTP) {
		t.Fatalf("err = %v", err)
	}
}

func TestTOTP_RejectsReplayOfSameCode(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	secret, _ := enrolled(t, f, u)
	ctx := context.Background()
	c := code(t, secret, f.clock.Now())

	if err := f.svc.VerifyTOTP(ctx, f.tenant, u.ID, c); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.VerifyTOTP(ctx, f.tenant, u.ID, c); !errors.Is(err, authn.ErrInvalidOTP) {
		t.Fatalf("replayed code accepted: err = %v", err)
	}
}

func TestTOTP_AcceptsOneStepClockSkew(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	secret, _ := enrolled(t, f, u)
	f.clock.Advance(30 * time.Second) // the previous step is now unused
	prev := code(t, secret, f.clock.Now().Add(-30*time.Second))
	if err := f.svc.VerifyTOTP(context.Background(), f.tenant, u.ID, prev); err != nil {
		t.Fatalf("one step of skew must be accepted: %v", err)
	}
}

func TestRecoveryCode_IsOneTime(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	_, recovery := enrolled(t, f, u)
	ctx := context.Background()

	if err := f.svc.UseRecoveryCode(ctx, f.tenant, u.ID, recovery[0]); err != nil {
		t.Fatalf("UseRecoveryCode: %v", err)
	}
	if err := f.svc.UseRecoveryCode(ctx, f.tenant, u.ID, recovery[0]); !errors.Is(err, authn.ErrInvalidOTP) {
		t.Fatalf("reused recovery code accepted: err = %v", err)
	}
	if err := f.svc.UseRecoveryCode(ctx, f.tenant, u.ID, "nope-nope"); !errors.Is(err, authn.ErrInvalidOTP) {
		t.Fatalf("unknown recovery code accepted: err = %v", err)
	}
}

func TestMFAFactors_ListAndDelete(t *testing.T) {
	f := setup(t, identity.Settings{})
	u := f.user(t, "alice", pw)
	enrolled(t, f, u)
	ctx := context.Background()

	factors, err := f.svc.ListMFAFactors(ctx, f.tenant.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var totpID string
	for _, fa := range factors {
		if fa.Type == "totp" {
			totpID = fa.ID.String()
		}
	}
	if totpID == "" {
		t.Fatalf("factors = %+v", factors)
	}
	if err := f.svc.DeleteMFAFactor(ctx, f.tenant.ID, u.ID, factors[0].ID); err != nil {
		t.Fatal(err)
	}
}
