package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

// WebAuthn builds the relying party configuration for a tenant. The RP ID is
// the host of the public base URL; all tenants share it.
func WebAuthn(baseURL string, tenant identity.Tenant) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID: u.Hostname(), RPDisplayName: "IdaaS (" + tenant.Name + ")", RPOrigins: []string{baseURL},
	})
}

// PasskeyUser adapts a user to webauthn.User. The user handle is the
// immutable internal user ID.
type PasskeyUser struct {
	User        identity.User
	Credentials []webauthn.Credential
}

func (u PasskeyUser) WebAuthnID() []byte                         { return u.User.ID[:] }
func (u PasskeyUser) WebAuthnName() string                       { return u.User.LoginID }
func (u PasskeyUser) WebAuthnDisplayName() string                { return u.User.Name() + " (" + u.User.LoginID + ")" }
func (u PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// PasskeyUser loads the user with their registered credentials.
func (s *Service) PasskeyUser(ctx context.Context, tenantID, userID uuid.UUID) (PasskeyUser, error) {
	u, err := identity.GetUserTx(ctx, s.pool, tenantID, userID)
	if err != nil {
		return PasskeyUser{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT credential FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	if err != nil {
		return PasskeyUser{}, err
	}
	creds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (webauthn.Credential, error) {
		var raw []byte
		var c webauthn.Credential
		if err := r.Scan(&raw); err != nil {
			return c, err
		}
		return c, json.Unmarshal(raw, &c)
	})
	return PasskeyUser{User: u, Credentials: creds}, err
}

// PasskeyUserByHandle resolves the user handle returned by a discoverable
// credential.
func (s *Service) PasskeyUserByHandle(ctx context.Context, tenantID uuid.UUID, handle []byte) (PasskeyUser, error) {
	id, err := uuid.FromBytes(handle)
	if err != nil {
		return PasskeyUser{}, identity.ErrNotFound
	}
	return s.PasskeyUser(ctx, tenantID, id)
}

func (s *Service) SavePasskey(ctx context.Context, tenantID, userID uuid.UUID, c *webauthn.Credential, label string) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO webauthn_credentials (id, tenant_id, user_id, credential_id, credential, label) VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), tenantID, userID, c.ID, raw, label); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "user.mfa_enrolled", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"type": "webauthn"}})
	})
}

// UpdatePasskeyAfterLogin stores the new signature counter and flags.
func (s *Service) UpdatePasskeyAfterLogin(ctx context.Context, tenantID uuid.UUID, c *webauthn.Credential) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE webauthn_credentials SET credential = $3, last_used_at = $4 WHERE tenant_id = $1 AND credential_id = $2`,
		tenantID, c.ID, raw, s.Now())
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("authn: unknown passkey")
	}
	return err
}
