package authn

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

// Session is an IdP session. The raw session ID lives only in the cookie;
// the database stores its hash.
type Session struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	UserID     uuid.UUID
	AuthTime   time.Time
	ACR        string
	AMR        []string
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateSession starts a new session and returns the raw session ID for the
// cookie. Always create a new session on login (session fixation defense).
func (s *Service) CreateSession(ctx context.Context, tenant identity.Tenant, userID uuid.UUID, acr string, amr []string) (string, Session, error) {
	raw := secret.NewToken()
	now := s.Now()
	sess := Session{
		ID: uuid.New(), TenantID: tenant.ID, UserID: userID, AuthTime: now, ACR: acr, AMR: amr,
		LastSeenAt: now, ExpiresAt: now.Add(tenant.Settings.SessionAbsolute()),
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id, tenant_id, user_id, session_id_hash, auth_time, acr, amr, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sess.ID, sess.TenantID, sess.UserID, secret.HashToken(raw), sess.AuthTime, sess.ACR, sess.AMR, sess.LastSeenAt, sess.ExpiresAt)
	if err != nil {
		return "", Session{}, err
	}
	return raw, sess, nil
}

// LookupSession returns the active session for a raw session ID and extends
// its idle timeout.
func (s *Service) LookupSession(ctx context.Context, tenant identity.Tenant, raw string) (Session, error) {
	if raw == "" {
		return Session{}, ErrNoSession
	}
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, auth_time, acr, amr, last_seen_at, expires_at
		FROM sessions WHERE tenant_id = $1 AND session_id_hash = $2 AND revoked_at IS NULL`,
		tenant.ID, secret.HashToken(raw)).
		Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.AuthTime, &sess.ACR, &sess.AMR, &sess.LastSeenAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	now := s.Now()
	if now.Sub(sess.LastSeenAt) > tenant.Settings.SessionIdle() || !now.Before(sess.ExpiresAt) {
		return Session{}, ErrNoSession
	}
	if _, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`, tenant.ID, sess.ID, now); err != nil {
		return Session{}, err
	}
	sess.LastSeenAt = now
	return sess, nil
}

// GetSession returns a session by ID without touching its idle timer.
func (s *Service) GetSession(ctx context.Context, tenantID, id uuid.UUID) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, auth_time, acr, amr, last_seen_at, expires_at
		FROM sessions WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.AuthTime, &sess.ACR, &sess.AMR, &sess.LastSeenAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	return sess, err
}

func (s *Service) RevokeSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, sessionID, s.Now())
	return err
}

func (s *Service) RevokeUserSessions(ctx context.Context, tenantID, userID uuid.UUID) error {
	return RevokeUserSessionsTx(ctx, s.pool, tenantID, userID, s.Now())
}

// RevokeUserSessionsTx revokes all of a user's sessions within q.
func RevokeUserSessionsTx(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE sessions SET revoked_at = $3 WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		tenantID, userID, now)
	return err
}
