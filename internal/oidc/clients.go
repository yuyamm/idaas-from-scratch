// Package oidc implements the OpenID Provider and OAuth 2.0 authorization
// server: clients, authorization codes, tokens, introspection, revocation and
// logout.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

type ClientType string

const (
	Confidential ClientType = "confidential"
	Public       ClientType = "public"
)

type AuthMethod string

const (
	ClientSecretBasic AuthMethod = "client_secret_basic"
	ClientSecretPost  AuthMethod = "client_secret_post"
	AuthNone          AuthMethod = "none"
)

var (
	ErrClientAuth     = errors.New("oidc: client authentication failed")
	ErrClientNotFound = errors.New("oidc: client not found")
	ErrClientConflict = errors.New("oidc: client conflict")
	ErrVersion        = errors.New("oidc: version mismatch")
)

type Client struct {
	ID                     uuid.UUID
	TenantID               uuid.UUID
	ClientID               string
	Name                   string
	Type                   ClientType
	FirstParty             bool
	AuthMethod             AuthMethod
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   *string
	AllowedScopes          []string
	AccessTokenFormat      string
	Version                int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func (c Client) AllowsGrant(g string) bool { return slices.Contains(c.GrantTypes, g) }

type NewClient struct {
	Name                   string
	Type                   ClientType
	FirstParty             bool
	AuthMethod             AuthMethod
	GrantTypes             []string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   *string
	AllowedScopes          []string
	AccessTokenFormat      string
}

type ClientPatch struct {
	Name                   *string
	FirstParty             *bool
	RedirectURIs           *[]string
	PostLogoutRedirectURIs *[]string
	BackchannelLogoutURI   **string
	AllowedScopes          *[]string
	AccessTokenFormat      *string
}

type ClientSecret struct {
	ID        uuid.UUID
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// ClientCredentials are what the client presented at an endpoint.
type ClientCredentials struct {
	ID     string
	Secret string
	Method AuthMethod
}

type ClientStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewClientStore(pool *pgxpool.Pool) *ClientStore {
	return &ClientStore{pool: pool, now: time.Now}
}

const clientColumns = `id, tenant_id, client_id, name, client_type, first_party, token_endpoint_auth_method, grant_types,
	redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, allowed_scopes, access_token_format, version, created_at, updated_at`

func scanClient(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.TenantID, &c.ClientID, &c.Name, &c.Type, &c.FirstParty, &c.AuthMethod, &c.GrantTypes,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.BackchannelLogoutURI, &c.AllowedScopes, &c.AccessTokenFormat,
		&c.Version, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrClientNotFound
	}
	return c, err
}

func clientEventData(c Client) map[string]any {
	return map[string]any{"id": c.ID, "client_id": c.ClientID, "name": c.Name, "client_type": c.Type}
}

// Create registers a client. For confidential clients the returned secret is
// the only time the plaintext is available.
func (s *ClientStore) Create(ctx context.Context, tenantID uuid.UUID, nc NewClient) (Client, string, error) {
	if nc.Type == Public {
		nc.AuthMethod = AuthNone
	} else if nc.AuthMethod == "" || nc.AuthMethod == AuthNone {
		nc.AuthMethod = ClientSecretBasic
	}
	if nc.AccessTokenFormat == "" {
		nc.AccessTokenFormat = "jwt"
	}
	nilToEmpty(&nc.RedirectURIs, &nc.PostLogoutRedirectURIs, &nc.AllowedScopes)
	var c Client
	var plain string
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		c, err = scanClient(tx.QueryRow(ctx, `INSERT INTO clients (id, tenant_id, client_id, name, client_type, first_party,
			token_endpoint_auth_method, grant_types, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri,
			allowed_scopes, access_token_format)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING `+clientColumns,
			uuid.New(), tenantID, secret.NewToken()[:22], nc.Name, nc.Type, nc.FirstParty, nc.AuthMethod, nc.GrantTypes,
			nc.RedirectURIs, nc.PostLogoutRedirectURIs, nc.BackchannelLogoutURI, nc.AllowedScopes, nc.AccessTokenFormat))
		if postgres.IsUniqueViolation(err) {
			return ErrClientConflict
		}
		if err != nil {
			return err
		}
		if c.Type == Confidential {
			if _, plain, err = s.addSecret(ctx, tx, tenantID, c.ID, nil); err != nil {
				return err
			}
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "client.created", TargetType: "client", TargetID: c.ID.String(), Data: clientEventData(c)})
	})
	return c, plain, err
}

func nilToEmpty(slices ...*[]string) {
	for _, s := range slices {
		if *s == nil {
			*s = []string{}
		}
	}
}

func (s *ClientStore) Get(ctx context.Context, tenantID, id uuid.UUID) (Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *ClientStore) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID))
}

func (s *ClientStore) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) ([]Client, string, error) {
	after := uuid.Nil
	if cursor != "" {
		var err error
		if after, err = uuid.Parse(cursor); err != nil {
			return nil, "", err
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT `+clientColumns+` FROM clients WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenantID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Client, error) { return scanClient(r) })
	if err != nil {
		return nil, "", err
	}
	if len(cs) > limit {
		cs = cs[:limit]
		return cs, cs[len(cs)-1].ID.String(), nil
	}
	return cs, "", nil
}

func (s *ClientStore) Update(ctx context.Context, tenantID, id uuid.UUID, expectedVersion int64, p ClientPatch) (Client, error) {
	var c Client
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return ErrVersion
		}
		if p.Name != nil {
			cur.Name = *p.Name
		}
		if p.FirstParty != nil {
			cur.FirstParty = *p.FirstParty
		}
		if p.RedirectURIs != nil {
			cur.RedirectURIs = *p.RedirectURIs
		}
		if p.PostLogoutRedirectURIs != nil {
			cur.PostLogoutRedirectURIs = *p.PostLogoutRedirectURIs
		}
		if p.BackchannelLogoutURI != nil {
			cur.BackchannelLogoutURI = *p.BackchannelLogoutURI
		}
		if p.AllowedScopes != nil {
			cur.AllowedScopes = *p.AllowedScopes
		}
		if p.AccessTokenFormat != nil {
			cur.AccessTokenFormat = *p.AccessTokenFormat
		}
		nilToEmpty(&cur.RedirectURIs, &cur.PostLogoutRedirectURIs, &cur.AllowedScopes)
		c, err = scanClient(tx.QueryRow(ctx, `UPDATE clients SET name = $3, first_party = $4, redirect_uris = $5,
			post_logout_redirect_uris = $6, backchannel_logout_uri = $7, allowed_scopes = $8, access_token_format = $9,
			version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 RETURNING `+clientColumns,
			tenantID, id, cur.Name, cur.FirstParty, cur.RedirectURIs, cur.PostLogoutRedirectURIs, cur.BackchannelLogoutURI,
			cur.AllowedScopes, cur.AccessTokenFormat))
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "client.updated", TargetType: "client", TargetID: c.ID.String(), Data: clientEventData(c)})
	})
	return c, err
}

// Delete removes a client; its codes and tokens go with it (ON DELETE CASCADE).
func (s *ClientStore) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM clients WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrClientNotFound
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "client.deleted", TargetType: "client", TargetID: id.String(), Data: map[string]any{"id": id}})
	})
}

func (s *ClientStore) addSecret(ctx context.Context, q postgres.Querier, tenantID, clientID uuid.UUID, expiresAt *time.Time) (ClientSecret, string, error) {
	plain := secret.NewToken()
	sec := ClientSecret{ID: uuid.New(), CreatedAt: s.now().UTC(), ExpiresAt: expiresAt}
	_, err := q.Exec(ctx, `INSERT INTO client_secrets (id, tenant_id, client_id, secret_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		sec.ID, tenantID, clientID, secret.HashToken(plain), expiresAt, sec.CreatedAt)
	return sec, plain, err
}

// AddSecret issues an additional secret so clients can rotate without downtime.
func (s *ClientStore) AddSecret(ctx context.Context, tenantID, clientID uuid.UUID, expiresAt *time.Time) (ClientSecret, string, error) {
	var sec ClientSecret
	var plain string
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE tenant_id = $1 AND id = $2`, tenantID, clientID))
		if err != nil {
			return err
		}
		if c.Type != Confidential {
			return ErrClientConflict
		}
		if sec, plain, err = s.addSecret(ctx, tx, tenantID, clientID, expiresAt); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "client.secret_created", TargetType: "client", TargetID: clientID.String(), Data: map[string]any{"secret_id": sec.ID}})
	})
	return sec, plain, err
}

func (s *ClientStore) ListSecrets(ctx context.Context, tenantID, clientID uuid.UUID) ([]ClientSecret, error) {
	if _, err := s.Get(ctx, tenantID, clientID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, created_at, expires_at FROM client_secrets WHERE tenant_id = $1 AND client_id = $2 ORDER BY created_at`, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ClientSecret, error) {
		var cs ClientSecret
		return cs, r.Scan(&cs.ID, &cs.CreatedAt, &cs.ExpiresAt)
	})
}

func (s *ClientStore) DeleteSecret(ctx context.Context, tenantID, clientID, secretID uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM client_secrets WHERE tenant_id = $1 AND client_id = $2 AND id = $3`, tenantID, clientID, secretID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrClientNotFound
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "client.secret_deleted", TargetType: "client", TargetID: clientID.String(), Data: map[string]any{"secret_id": secretID}})
	})
}

// Authenticate verifies the credentials a client presented. The method must
// match the registered token_endpoint_auth_method.
func (s *ClientStore) Authenticate(ctx context.Context, tenantID uuid.UUID, cred ClientCredentials) (Client, error) {
	c, err := s.GetByClientID(ctx, tenantID, cred.ID)
	if errors.Is(err, ErrClientNotFound) {
		return Client{}, ErrClientAuth
	}
	if err != nil {
		return Client{}, err
	}
	if cred.Method != c.AuthMethod {
		return Client{}, ErrClientAuth
	}
	if c.AuthMethod == AuthNone {
		return c, nil
	}
	if cred.Secret == "" {
		return Client{}, ErrClientAuth
	}
	rows, err := s.pool.Query(ctx, `SELECT secret_hash FROM client_secrets
		WHERE tenant_id = $1 AND client_id = $2 AND (expires_at IS NULL OR expires_at > $3)`, tenantID, c.ID, s.now())
	if err != nil {
		return Client{}, err
	}
	hashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return Client{}, err
	}
	presented := []byte(secret.HashToken(cred.Secret))
	for _, h := range hashes {
		if subtle.ConstantTimeCompare(presented, []byte(h)) == 1 {
			return c, nil
		}
	}
	return Client{}, ErrClientAuth
}
