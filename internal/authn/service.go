// Package authn authenticates users (password, MFA) and manages IdP sessions.
package authn

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

var (
	// ErrInvalidCredentials is returned for every password failure (unknown
	// user, wrong password, locked or disabled account) so responses do not
	// reveal whether an account exists.
	ErrInvalidCredentials = errors.New("authn: invalid credentials")
	ErrWeakPassword       = errors.New("authn: password does not meet the policy")
	ErrBreachedPassword   = errors.New("authn: password appears in a data breach")
	ErrNoSession          = errors.New("authn: no valid session")
)

// Authentication context class references (acr).
const (
	ACRPassword = "urn:idaas:acr:pwd"
	ACRMFA      = "urn:idaas:acr:mfa"
)

// BreachChecker reports whether a password is known to be breached.
type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

type Service struct {
	pool   *pgxpool.Pool
	hasher *PasswordHasher
	now    func() time.Time
	breach BreachChecker
	enc    crypto.Encrypter
	// dummyHash is verified for unknown users so the response time does not
	// reveal whether the account exists.
	dummyHash string
}

type Option func(*Service)

func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func WithBreachChecker(b BreachChecker) Option { return func(s *Service) { s.breach = b } }

func NewService(pool *pgxpool.Pool, hasher *PasswordHasher, opts ...Option) *Service {
	s := &Service{pool: pool, hasher: hasher, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	h, err := hasher.Hash(secret.NewToken())
	if err != nil {
		panic(err)
	}
	s.dummyHash = h
	return s
}

func (s *Service) Now() time.Time { return s.now().UTC() }

// SetPassword validates and stores a new password and revokes the user's
// existing sessions.
func (s *Service) SetPassword(ctx context.Context, tenant identity.Tenant, userID uuid.UUID, password string) error {
	if utf8.RuneCountInString(password) < tenant.Settings.PasswordMin() {
		return ErrWeakPassword
	}
	if tenant.Settings.PasswordBreachCheck && s.breach != nil {
		breached, err := s.breach.IsBreached(ctx, password)
		if err != nil {
			return fmt.Errorf("authn: breach check: %w", err)
		}
		if breached {
			return ErrBreachedPassword
		}
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return err
	}
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := identity.GetUserTx(ctx, tx, tenant.ID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO password_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = now()`,
			userID, tenant.ID, hash); err != nil {
			return err
		}
		if err := RevokeUserSessionsTx(ctx, tx, tenant.ID, userID, s.Now()); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{
			TenantID: tenant.ID, Type: "user.password_changed", TargetType: "user", TargetID: userID.String(),
		})
	})
}

// VerifyPassword checks a login ID and password, applying account lockout.
// Failures are committed (failure counters, audit events) before returning.
func (s *Service) VerifyPassword(ctx context.Context, tenant identity.Tenant, loginID, password string) (identity.User, error) {
	var user identity.User
	var authErr error
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		u, hash, err := lockUserForLogin(ctx, tx, tenant.ID, loginID)
		if errors.Is(err, identity.ErrNotFound) {
			s.hasher.Verify(password, s.dummyHash)
			authErr = ErrInvalidCredentials
			return recordLogin(ctx, tx, tenant.ID, loginID, audit.Failure, "unknown_user")
		}
		if err != nil {
			return err
		}
		now := s.Now()

		if u.Status == identity.StatusLocked && u.LockedUntil != nil && !now.Before(*u.LockedUntil) {
			u.Status, u.FailedLoginCount, u.LockedUntil = identity.StatusActive, 0, nil
		}
		if u.Status != identity.StatusActive || hash == "" {
			s.hasher.Verify(password, s.dummyHash)
			authErr = ErrInvalidCredentials
			if _, err := tx.Exec(ctx, `UPDATE users SET status = $3, failed_login_count = $4, locked_until = $5 WHERE tenant_id = $1 AND id = $2`,
				tenant.ID, u.ID, u.Status, u.FailedLoginCount, u.LockedUntil); err != nil {
				return err
			}
			return recordLogin(ctx, tx, tenant.ID, u.ID.String(), audit.Failure, "account_"+string(u.Status))
		}

		ok, err := s.hasher.Verify(password, hash)
		if err != nil {
			return err
		}
		if !ok {
			authErr = ErrInvalidCredentials
			return s.registerFailure(ctx, tx, tenant, u, now)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE users SET status = 'active', failed_login_count = 0, locked_until = NULL, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenant.ID, u.ID); err != nil {
			return err
		}
		if s.hasher.NeedsRehash(hash) {
			if newHash, err := s.hasher.Hash(password); err == nil {
				if _, err := tx.Exec(ctx, `UPDATE password_credentials SET password_hash = $3, updated_at = now() WHERE tenant_id = $1 AND user_id = $2`,
					tenant.ID, u.ID, newHash); err != nil {
					return err
				}
			}
		}
		u.Status, u.FailedLoginCount, u.LockedUntil = identity.StatusActive, 0, nil
		user = u
		return nil
	})
	if err != nil {
		return identity.User{}, err
	}
	if authErr != nil {
		return identity.User{}, authErr
	}
	return user, nil
}

func (s *Service) registerFailure(ctx context.Context, tx pgx.Tx, tenant identity.Tenant, u identity.User, now time.Time) error {
	failed := u.FailedLoginCount + 1
	status := identity.StatusActive
	var lockedUntil *time.Time
	if failed >= tenant.Settings.LockoutAfter() {
		status = identity.StatusLocked
		t := now.Add(tenant.Settings.LockoutDuration())
		lockedUntil = &t
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET failed_login_count = $3, status = $4, locked_until = $5, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant.ID, u.ID, failed, status, lockedUntil); err != nil {
		return err
	}
	if err := recordLogin(ctx, tx, tenant.ID, u.ID.String(), audit.Failure, "wrong_password"); err != nil {
		return err
	}
	if status == identity.StatusLocked {
		return audit.Record(ctx, tx, audit.Event{
			TenantID: tenant.ID, Type: "user.locked", TargetType: "user", TargetID: u.ID.String(),
			Data: map[string]any{"locked_until": lockedUntil}, Actor: &audit.Actor{Type: audit.ActorSystem},
		})
	}
	return nil
}

// RecordLoginSuccess records a completed login (after MFA, if any).
func (s *Service) RecordLoginSuccess(ctx context.Context, tenantID, userID uuid.UUID, amr []string) error {
	return audit.Record(ctx, s.pool, audit.Event{
		TenantID: tenantID, Type: "user.login", TargetType: "user", TargetID: userID.String(),
		Data: map[string]any{"amr": amr}, Actor: &audit.Actor{Type: audit.ActorUser, ID: userID.String()},
	})
}

func recordLogin(ctx context.Context, q postgres.Querier, tenantID uuid.UUID, target string, r audit.Result, reason string) error {
	return audit.Record(ctx, q, audit.Event{
		TenantID: tenantID, Type: "user.login", TargetType: "user", TargetID: target, Result: r,
		Data: map[string]any{"reason": reason}, Actor: &audit.Actor{Type: audit.ActorUser},
	})
}

func lockUserForLogin(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, loginID string) (identity.User, string, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM users WHERE tenant_id = $1 AND lower(login_id) = lower($2) AND deleted_at IS NULL
		FOR UPDATE`, tenantID, loginID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, "", identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, "", err
	}
	u, err := identity.GetUserTx(ctx, tx, tenantID, id)
	if err != nil {
		return u, "", err
	}
	var hash string
	err = tx.QueryRow(ctx, `SELECT password_hash FROM password_credentials WHERE tenant_id = $1 AND user_id = $2`, tenantID, id).Scan(&hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return u, "", err
	}
	return u, hash, nil
}
