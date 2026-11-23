package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
)

// Settings are per-tenant policy values. Zero values mean "use the default".
type Settings struct {
	PasswordMinLength             int  `json:"password_min_length,omitempty"`
	PasswordBreachCheck           bool `json:"password_breach_check,omitempty"`
	MFARequired                   bool `json:"mfa_required,omitempty"`
	LockoutThreshold              int  `json:"lockout_threshold,omitempty"`
	LockoutDurationSeconds        int  `json:"lockout_duration_seconds,omitempty"`
	SessionIdleTimeoutSeconds     int  `json:"session_idle_timeout_seconds,omitempty"`
	SessionAbsoluteTimeoutSeconds int  `json:"session_absolute_timeout_seconds,omitempty"`
	AuthorizationCodeTTLSeconds   int  `json:"authorization_code_ttl_seconds,omitempty"`
	AccessTokenTTLSeconds         int  `json:"access_token_ttl_seconds,omitempty"`
	IDTokenTTLSeconds             int  `json:"id_token_ttl_seconds,omitempty"`
	RefreshTokenTTLSeconds        int  `json:"refresh_token_ttl_seconds,omitempty"`
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func secs(n int) time.Duration { return time.Duration(n) * time.Second }

func (s Settings) PasswordMin() int  { return orDefault(s.PasswordMinLength, 12) }
func (s Settings) LockoutAfter() int { return orDefault(s.LockoutThreshold, 5) }
func (s Settings) LockoutDuration() time.Duration {
	return secs(orDefault(s.LockoutDurationSeconds, 900))
}
func (s Settings) SessionIdle() time.Duration {
	return secs(orDefault(s.SessionIdleTimeoutSeconds, 1800))
}
func (s Settings) SessionAbsolute() time.Duration {
	return secs(orDefault(s.SessionAbsoluteTimeoutSeconds, 43200))
}
func (s Settings) AuthorizationCodeTTL() time.Duration {
	return secs(orDefault(s.AuthorizationCodeTTLSeconds, 60))
}
func (s Settings) AccessTokenTTL() time.Duration {
	return secs(orDefault(s.AccessTokenTTLSeconds, 600))
}
func (s Settings) IDTokenTTL() time.Duration { return secs(orDefault(s.IDTokenTTLSeconds, 600)) }
func (s Settings) RefreshTokenTTL() time.Duration {
	return secs(orDefault(s.RefreshTokenTTLSeconds, 2592000))
}

const tenantColumns = `id, slug, name, settings, version, created_at, updated_at`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	var raw []byte
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &raw, &t.Version, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	return t, json.Unmarshal(raw, &t.Settings)
}

func (s *Store) CreateTenant(ctx context.Context, slug, name string) (Tenant, error) {
	return s.CreateTenantWithSettings(ctx, slug, name, Settings{})
}

func (s *Store) CreateTenantWithSettings(ctx context.Context, slug, name string, st Settings) (Tenant, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return Tenant{}, err
	}
	t, err := scanTenant(s.pool.QueryRow(ctx,
		`INSERT INTO tenants (id, slug, name, settings) VALUES ($1, $2, $3, $4) RETURNING `+tenantColumns,
		uuid.New(), slug, name, raw))
	return t, wrapWrite(err)
}

func (s *Store) GetTenant(ctx context.Context, id uuid.UUID) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, id))
}

func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE slug = $1`, slug))
}

func (s *Store) UpdateTenant(ctx context.Context, id uuid.UUID, expectedVersion int64, name string, st Settings) (Tenant, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return Tenant{}, err
	}
	var t Tenant
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		t, err = scanTenant(tx.QueryRow(ctx, `UPDATE tenants SET name = $3, settings = $4, version = version + 1, updated_at = now()
			WHERE id = $1 AND ($2 = 0 OR version = $2) RETURNING `+tenantColumns, id, expectedVersion, name, raw))
		if errors.Is(err, ErrNotFound) {
			if _, gerr := s.GetTenant(ctx, id); gerr == nil {
				return ErrVersionMismatch
			}
		}
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: id, Type: "tenant.updated", TargetType: "tenant", TargetID: id.String(),
			Data: map[string]any{"name": name, "settings": st}})
	})
	return t, err
}

func (s *Store) ListTenants(ctx context.Context, limit int, cursor string) ([]Tenant, string, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE id > $1 ORDER BY id LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	ts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Tenant, error) { return scanTenant(r) })
	if err != nil {
		return nil, "", err
	}
	return page(ts, limit, func(t Tenant) uuid.UUID { return t.ID })
}
