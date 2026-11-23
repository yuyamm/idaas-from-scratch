// Package keys manages per-tenant signing keys, their rotation and the JWKS.
//
// Keys move next -> current -> retiring -> retired. The next key is published
// in the JWKS before it signs anything, and a retiring key stays published
// until every token it signed has expired.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

const (
	Alg     = "RS256"
	rsaBits = 2048
)

type Status string

const (
	StatusNext     Status = "next"
	StatusCurrent  Status = "current"
	StatusRetiring Status = "retiring"
	StatusRetired  Status = "retired"
)

type Key struct {
	KID         string
	Alg         string
	Status      Status
	PublicJWK   jose.JSONWebKey
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RetiredAt   *time.Time
}

type Service struct {
	pool *pgxpool.Pool
	enc  crypto.Encrypter
	now  func() time.Time
}

type Option func(*Service)

func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func NewService(pool *pgxpool.Pool, enc crypto.Encrypter, opts ...Option) *Service {
	s := &Service{pool: pool, enc: enc, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

func aad(tenantID uuid.UUID, kid string) []byte {
	return []byte("signing_key:" + tenantID.String() + ":" + kid)
}

func (s *Service) generate(ctx context.Context, q postgres.Querier, tenantID uuid.UUID, status Status) error {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return err
	}
	kid := uuid.NewString()
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: Alg, Use: "sig"}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	ct, keyID, err := s.enc.Encrypt(der, aad(tenantID, kid))
	if err != nil {
		return err
	}
	var activated *time.Time
	if status == StatusCurrent {
		now := s.now().UTC()
		activated = &now
	}
	_, err = q.Exec(ctx, `INSERT INTO signing_keys (kid, tenant_id, alg, status, public_jwk, private_key_encrypted, encryption_key_id, created_at, activated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		kid, tenantID, Alg, status, pubJSON, ct, keyID, s.now().UTC(), activated)
	return err
}

// ensure creates the current and next keys for a tenant that has none.
func (s *Service) ensure(ctx context.Context, tenantID uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize key creation per tenant.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, "keys:"+tenantID.String()); err != nil {
			return err
		}
		var hasCurrent, hasNext bool
		if err := tx.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM signing_keys WHERE tenant_id = $1 AND status = 'current'),
			EXISTS (SELECT 1 FROM signing_keys WHERE tenant_id = $1 AND status = 'next')`, tenantID).Scan(&hasCurrent, &hasNext); err != nil {
			return err
		}
		if !hasCurrent {
			if err := s.generate(ctx, tx, tenantID, StatusCurrent); err != nil {
				return err
			}
		}
		if !hasNext {
			return s.generate(ctx, tx, tenantID, StatusNext)
		}
		return nil
	})
}

// List returns all keys of a tenant, newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Key, error) {
	if err := s.ensure(ctx, tenantID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT kid, alg, status, public_jwk, created_at, activated_at, retired_at
		FROM signing_keys WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Key, error) {
		var k Key
		var raw []byte
		if err := r.Scan(&k.KID, &k.Alg, &k.Status, &raw, &k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
			return k, err
		}
		return k, json.Unmarshal(raw, &k.PublicJWK)
	})
}

// JWKS returns the public keys that verifiers may encounter.
func (s *Service) JWKS(ctx context.Context, tenantID uuid.UUID) (jose.JSONWebKeySet, error) {
	all, err := s.List(ctx, tenantID)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, k := range all {
		if k.Status != StatusRetired {
			set.Keys = append(set.Keys, k.PublicJWK)
		}
	}
	return set, nil
}

func (s *Service) currentSigner(ctx context.Context, tenantID uuid.UUID, typ string) (jose.Signer, error) {
	if err := s.ensure(ctx, tenantID); err != nil {
		return nil, err
	}
	var (
		kid, keyID string
		ct         []byte
	)
	err := s.pool.QueryRow(ctx, `SELECT kid, private_key_encrypted, encryption_key_id FROM signing_keys
		WHERE tenant_id = $1 AND status = 'current'`, tenantID).Scan(&kid, &ct, &keyID)
	if err != nil {
		return nil, fmt.Errorf("keys: load current key: %w", err)
	}
	der, err := s.enc.Decrypt(ct, keyID, aad(tenantID, kid))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), kid)
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, opts)
}

// SignJWT signs claims with the tenant's current key. typ is the JWT "typ"
// header (JWT, at+jwt, logout+jwt).
func (s *Service) SignJWT(ctx context.Context, tenantID uuid.UUID, typ string, claims any) (string, error) {
	signer, err := s.currentSigner(ctx, tenantID, typ)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Verify checks a compact JWS against the tenant's published keys and returns
// its payload.
func (s *Service) Verify(ctx context.Context, tenantID uuid.UUID, token string) ([]byte, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("keys: want exactly one signature")
	}
	set, err := s.JWKS(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	candidates := set.Key(jws.Signatures[0].Header.KeyID)
	if len(candidates) == 0 {
		return nil, errors.New("keys: unknown kid")
	}
	return jws.Verify(candidates[0].Key)
}

// Rotate promotes next to current, moves current to retiring and creates a
// new next key.
func (s *Service) Rotate(ctx context.Context, tenantID uuid.UUID) error {
	if err := s.ensure(ctx, tenantID); err != nil {
		return err
	}
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, "keys:"+tenantID.String()); err != nil {
			return err
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'retiring', retiring_at = $2 WHERE tenant_id = $1 AND status = 'current'`, tenantID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE signing_keys SET status = 'current', activated_at = $2 WHERE tenant_id = $1 AND status = 'next'`, tenantID, now); err != nil {
			return err
		}
		if err := s.generate(ctx, tx, tenantID, StatusNext); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "signing_key.rotated", TargetType: "tenant", TargetID: tenantID.String()})
	})
}

// RetireExpired retires keys that have been retiring longer than the maximum
// lifetime of any token they could have signed.
func (s *Service) RetireExpired(ctx context.Context, tenantID uuid.UUID, maxTokenLifetime time.Duration) error {
	now := s.now().UTC()
	_, err := s.pool.Exec(ctx, `UPDATE signing_keys SET status = 'retired', retired_at = $2
		WHERE tenant_id = $1 AND status = 'retiring' AND retiring_at <= $3`, tenantID, now, now.Add(-maxTokenLifetime))
	return err
}
