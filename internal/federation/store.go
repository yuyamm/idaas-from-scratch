// Package federation logs users in with external OIDC IdPs (IdaaS as RP)
// and serves SAML SPs (IdaaS as SAML IdP).
package federation

import (
	"context"
	"encoding/xml"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

var (
	ErrNotFound = errors.New("federation: not found")
	ErrConflict = errors.New("federation: conflict")
	ErrInvalid  = errors.New("federation: invalid input")
)

type IdentityProvider struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Type        string
	Issuer      string
	ClientID    string
	Scopes      []string
	AllowSignup bool
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type IdentityProviderInput struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret *string
	Scopes       []string
	AllowSignup  bool
}

type Store struct {
	pool *pgxpool.Pool
	enc  crypto.Encrypter
}

func NewStore(pool *pgxpool.Pool, enc crypto.Encrypter) *Store { return &Store{pool: pool, enc: enc} }

func idpAAD(tenantID, id uuid.UUID) []byte {
	return []byte("idp:" + tenantID.String() + ":" + id.String())
}

const idpColumns = `id, tenant_id, name, type, issuer, client_id, scopes, allow_signup, version, created_at, updated_at`

func scanIdP(r pgx.Row) (IdentityProvider, error) {
	var p IdentityProvider
	err := r.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.Issuer, &p.ClientID, &p.Scopes, &p.AllowSignup, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) CreateIdP(ctx context.Context, tenantID uuid.UUID, in IdentityProviderInput) (IdentityProvider, error) {
	if in.Name == "" || in.Issuer == "" || in.ClientID == "" {
		return IdentityProvider{}, ErrInvalid
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "email", "profile"}
	}
	id := uuid.New()
	secret := ""
	if in.ClientSecret != nil {
		secret = *in.ClientSecret
	}
	ct, keyID, err := s.enc.Encrypt([]byte(secret), idpAAD(tenantID, id))
	if err != nil {
		return IdentityProvider{}, err
	}
	var p IdentityProvider
	err = postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		p, err = scanIdP(tx.QueryRow(ctx, `INSERT INTO identity_providers (id, tenant_id, name, type, issuer, client_id,
			client_secret_encrypted, encryption_key_id, scopes, allow_signup) VALUES ($1, $2, $3, 'oidc', $4, $5, $6, $7, $8, $9)
			RETURNING `+idpColumns, id, tenantID, in.Name, in.Issuer, in.ClientID, ct, keyID, in.Scopes, in.AllowSignup))
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "identity_provider.created", TargetType: "identity_provider", TargetID: id.String(),
			Data: map[string]any{"id": id, "name": in.Name, "issuer": in.Issuer}})
	})
	return p, err
}

func (s *Store) GetIdP(ctx context.Context, tenantID, id uuid.UUID) (IdentityProvider, error) {
	return scanIdP(s.pool.QueryRow(ctx, `SELECT `+idpColumns+` FROM identity_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) ListIdPs(ctx context.Context, tenantID uuid.UUID) ([]IdentityProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+idpColumns+` FROM identity_providers WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (IdentityProvider, error) { return scanIdP(r) })
}

func (s *Store) UpdateIdP(ctx context.Context, tenantID, id uuid.UUID, expectedVersion int64, in IdentityProviderInput) (IdentityProvider, error) {
	var p IdentityProvider
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := scanIdP(tx.QueryRow(ctx, `SELECT `+idpColumns+` FROM identity_providers WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return ErrConflict
		}
		if in.Name != "" {
			cur.Name = in.Name
		}
		if in.Issuer != "" {
			cur.Issuer = in.Issuer
		}
		if in.ClientID != "" {
			cur.ClientID = in.ClientID
		}
		if len(in.Scopes) > 0 {
			cur.Scopes = in.Scopes
		}
		cur.AllowSignup = in.AllowSignup
		p, err = scanIdP(tx.QueryRow(ctx, `UPDATE identity_providers SET name = $3, issuer = $4, client_id = $5, scopes = $6, allow_signup = $7,
			version = version + 1, updated_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING `+idpColumns,
			tenantID, id, cur.Name, cur.Issuer, cur.ClientID, cur.Scopes, cur.AllowSignup))
		if err != nil {
			return err
		}
		if in.ClientSecret != nil {
			ct, keyID, err := s.enc.Encrypt([]byte(*in.ClientSecret), idpAAD(tenantID, id))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE identity_providers SET client_secret_encrypted = $3, encryption_key_id = $4 WHERE tenant_id = $1 AND id = $2`, tenantID, id, ct, keyID); err != nil {
				return err
			}
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "identity_provider.updated", TargetType: "identity_provider", TargetID: id.String()})
	})
	return p, err
}

func (s *Store) DeleteIdP(ctx context.Context, tenantID, id uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "identity_provider.deleted", TargetType: "identity_provider", TargetID: id.String()})
	})
}

func (s *Store) clientSecret(ctx context.Context, tenantID, id uuid.UUID) (string, error) {
	var ct []byte
	var keyID string
	if err := s.pool.QueryRow(ctx, `SELECT client_secret_encrypted, encryption_key_id FROM identity_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&ct, &keyID); err != nil {
		return "", err
	}
	pt, err := s.enc.Decrypt(ct, keyID, idpAAD(tenantID, id))
	return string(pt), err
}

// ---------------------------------------------------------------- SAML service providers

type SAMLServiceProvider struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	EntityID    string
	MetadataXML string
	CreatedAt   time.Time
}

func (s *Store) CreateSAMLSP(ctx context.Context, tenantID uuid.UUID, metadataXML string) (SAMLServiceProvider, error) {
	var ed struct {
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal([]byte(metadataXML), &ed); err != nil || ed.EntityID == "" {
		return SAMLServiceProvider{}, ErrInvalid
	}
	sp := SAMLServiceProvider{ID: uuid.New(), TenantID: tenantID, EntityID: ed.EntityID, MetadataXML: metadataXML}
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO saml_service_providers (id, tenant_id, entity_id, metadata_xml) VALUES ($1, $2, $3, $4) RETURNING created_at`,
			sp.ID, tenantID, sp.EntityID, metadataXML).Scan(&sp.CreatedAt)
		if postgres.IsUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "saml_service_provider.created", TargetType: "saml_service_provider",
			TargetID: sp.ID.String(), Data: map[string]any{"entity_id": sp.EntityID}})
	})
	return sp, err
}

func (s *Store) ListSAMLSPs(ctx context.Context, tenantID uuid.UUID) ([]SAMLServiceProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tenant_id, entity_id, metadata_xml, created_at FROM saml_service_providers WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SAMLServiceProvider, error) {
		var sp SAMLServiceProvider
		return sp, r.Scan(&sp.ID, &sp.TenantID, &sp.EntityID, &sp.MetadataXML, &sp.CreatedAt)
	})
}

func (s *Store) GetSAMLSPByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	err := s.pool.QueryRow(ctx, `SELECT id, tenant_id, entity_id, metadata_xml, created_at FROM saml_service_providers WHERE tenant_id = $1 AND entity_id = $2`,
		tenantID, entityID).Scan(&sp.ID, &sp.TenantID, &sp.EntityID, &sp.MetadataXML, &sp.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return sp, ErrNotFound
	}
	return sp, err
}

func (s *Store) DeleteSAMLSP(ctx context.Context, tenantID, id uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM saml_service_providers WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "saml_service_provider.deleted", TargetType: "saml_service_provider", TargetID: id.String()})
	})
}
