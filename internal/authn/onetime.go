package authn

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

var ErrInvalidToken = errors.New("authn: invalid or expired token")

const (
	purposePasswordReset     = "password_reset"
	purposeEmailVerification = "email_verification"
	passwordResetTTL         = 30 * time.Minute
	emailVerificationTTL     = 24 * time.Hour
)

func (s *Service) issueToken(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID, purpose string, ttl time.Duration) (string, error) {
	raw := secret.NewToken()
	_, err := q.Exec(ctx, `INSERT INTO one_time_tokens (token_hash, tenant_id, user_id, purpose, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		secret.HashToken(raw), tenantID, userID, purpose, s.Now().Add(ttl))
	return raw, err
}

func (s *Service) consumeToken(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, raw, purpose string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := tx.QueryRow(ctx, `UPDATE one_time_tokens SET consumed_at = $4
		WHERE token_hash = $1 AND tenant_id = $2 AND purpose = $3 AND consumed_at IS NULL AND expires_at > $4
		RETURNING user_id`, secret.HashToken(raw), tenantID, purpose, s.Now()).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInvalidToken
	}
	return userID, err
}

// RequestPasswordReset issues a reset token when loginOrEmail matches a user.
// ok is false for unknown users; callers must respond identically in both
// cases so the response does not reveal whether the account exists.
func (s *Service) RequestPasswordReset(ctx context.Context, tenant identity.Tenant, loginOrEmail string) (token string, user identity.User, ok bool, err error) {
	ids := identity.NewStore(s.pool)
	user, err = ids.FindUserByEmail(ctx, tenant.ID, loginOrEmail)
	if errors.Is(err, identity.ErrNotFound) {
		user, err = ids.FindUserByLoginID(ctx, tenant.ID, loginOrEmail)
	}
	if errors.Is(err, identity.ErrNotFound) || (err == nil && user.Status == identity.StatusDisabled) {
		return "", identity.User{}, false, nil
	}
	if err != nil {
		return "", identity.User{}, false, err
	}
	token, err = s.issueToken(ctx, s.pool, tenant.ID, user.ID, purposePasswordReset, passwordResetTTL)
	if err != nil {
		return "", identity.User{}, false, err
	}
	return token, user, true, nil
}

// ResetPassword consumes a reset token and sets the new password. Existing
// sessions are revoked.
func (s *Service) ResetPassword(ctx context.Context, tenant identity.Tenant, token, newPassword string) error {
	if len([]rune(newPassword)) < tenant.Settings.PasswordMin() {
		return ErrWeakPassword
	}
	var userID uuid.UUID
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		userID, err = s.consumeToken(ctx, tx, tenant.ID, token, purposePasswordReset)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.SetPassword(ctx, tenant, userID, newPassword); err != nil {
		return err
	}
	// A successful reset proves control of the mailbox and clears a lockout.
	_, err = s.pool.Exec(ctx, `UPDATE users SET status = 'active', failed_login_count = 0, locked_until = NULL
		WHERE tenant_id = $1 AND id = $2 AND status = 'locked'`, tenant.ID, userID)
	return err
}

func (s *Service) IssueEmailVerification(ctx context.Context, tenant identity.Tenant, userID uuid.UUID) (string, error) {
	return s.issueToken(ctx, s.pool, tenant.ID, userID, purposeEmailVerification, emailVerificationTTL)
}

func (s *Service) VerifyEmail(ctx context.Context, tenant identity.Tenant, token string) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		userID, err := s.consumeToken(ctx, tx, tenant.ID, token, purposeEmailVerification)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET email_verified = true, version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenant.ID, userID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{
			TenantID: tenant.ID, Type: "user.updated", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"email_verified": true}, Actor: &audit.Actor{Type: audit.ActorUser, ID: userID.String()},
		})
	})
}
