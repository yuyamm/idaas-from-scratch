// Package identity manages tenants, users, groups and roles.
//
// Every operation on tenant-owned data takes the tenant ID as an argument and
// filters by it, so callers cannot reach another tenant's data by accident.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

var (
	ErrNotFound = errors.New("identity: not found")
	ErrConflict = errors.New("identity: conflict")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
	StatusLocked   Status = "locked"
)

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	Settings  Settings
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	LoginID          string
	Email            string
	EmailVerified    bool
	GivenName        string
	FamilyName       string
	Status           Status
	FailedLoginCount int
	LockedUntil      *time.Time
	Version          int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
}

func (u User) Name() string {
	switch {
	case u.GivenName == "":
		return u.FamilyName
	case u.FamilyName == "":
		return u.GivenName
	default:
		return u.GivenName + " " + u.FamilyName
	}
}

type NewUser struct {
	LoginID       string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the pool so other modules can run identity operations in their
// own transactions.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const userColumns = `id, tenant_id, login_id, email, email_verified, given_name, family_name, status,
	failed_login_count, locked_until, version, created_at, updated_at, deleted_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.LoginID, &u.Email, &u.EmailVerified, &u.GivenName, &u.FamilyName,
		&u.Status, &u.FailedLoginCount, &u.LockedUntil, &u.Version, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func wrapWrite(err error) error {
	if postgres.IsUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) CreateUser(ctx context.Context, tenantID uuid.UUID, nu NewUser) (User, error) {
	return CreateUserTx(ctx, s.pool, tenantID, nu)
}

func CreateUserTx(ctx context.Context, q postgres.Querier, tenantID uuid.UUID, nu NewUser) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `
		INSERT INTO users (id, tenant_id, login_id, email, email_verified, given_name, family_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+userColumns,
		uuid.New(), tenantID, nu.LoginID, nu.Email, nu.EmailVerified, nu.GivenName, nu.FamilyName))
	return u, wrapWrite(err)
}

func (s *Store) GetUser(ctx context.Context, tenantID, userID uuid.UUID) (User, error) {
	return GetUserTx(ctx, s.pool, tenantID, userID)
}

func GetUserTx(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID) (User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenantID, userID))
}

func (s *Store) FindUserByLoginID(ctx context.Context, tenantID uuid.UUID, loginID string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND lower(login_id) = lower($2) AND deleted_at IS NULL`,
		tenantID, loginID))
}

func (s *Store) FindUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND lower(email) = lower($2) AND deleted_at IS NULL`,
		tenantID, email))
}

// SetStatus changes a user's status. Locking is handled by authn.
func (s *Store) SetStatus(ctx context.Context, tenantID, userID uuid.UUID, st Status) error {
	return SetStatusTx(ctx, s.pool, tenantID, userID, st)
}

func SetStatusTx(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID, st Status) error {
	tag, err := q.Exec(ctx, `
		UPDATE users SET status = $3, failed_login_count = 0, locked_until = NULL,
			version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, userID, st)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
