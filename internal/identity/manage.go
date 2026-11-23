package identity

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

var ErrVersionMismatch = errors.New("identity: version mismatch")

type Group struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Name      string
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Role struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description string
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserPatch struct {
	LoginID    *string
	Email      *string
	GivenName  *string
	FamilyName *string
}

type UserFilter struct {
	LoginID string
	Email   string
	Status  Status
}

func isFKViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return postgres.InTx(ctx, s.pool, fn)
}

func event(tenantID uuid.UUID, typ, targetType string, targetID uuid.UUID, data any) audit.Event {
	return audit.Event{TenantID: tenantID, Type: typ, TargetType: targetType, TargetID: targetID.String(), Data: data}
}

// ---------------------------------------------------------------- users

// CreateUserAudited creates a user and records user.created.
func (s *Store) CreateUserAudited(ctx context.Context, tenantID uuid.UUID, nu NewUser) (User, error) {
	var u User
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		if u, err = CreateUserTx(ctx, tx, tenantID, nu); err != nil {
			return err
		}
		return audit.Record(ctx, tx, event(tenantID, "user.created", "user", u.ID, userEventData(u)))
	})
	return u, err
}

func userEventData(u User) map[string]any {
	return map[string]any{"id": u.ID, "user_name": u.LoginID, "email": u.Email, "email_verified": u.EmailVerified,
		"given_name": u.GivenName, "family_name": u.FamilyName, "status": u.Status}
}

func (s *Store) UpdateUser(ctx context.Context, tenantID, userID uuid.UUID, expectedVersion int64, p UserPatch) (User, error) {
	var u User
	err := s.tx(ctx, func(tx pgx.Tx) error {
		cur, err := GetUserTx(ctx, tx, tenantID, userID)
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return ErrVersionMismatch
		}
		next := cur
		if p.LoginID != nil {
			next.LoginID = *p.LoginID
		}
		if p.Email != nil && *p.Email != cur.Email {
			next.Email, next.EmailVerified = *p.Email, false
		}
		if p.GivenName != nil {
			next.GivenName = *p.GivenName
		}
		if p.FamilyName != nil {
			next.FamilyName = *p.FamilyName
		}
		u, err = scanUser(tx.QueryRow(ctx, `
			UPDATE users SET login_id = $3, email = $4, email_verified = $5, given_name = $6, family_name = $7,
				version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 RETURNING `+userColumns,
			tenantID, userID, next.LoginID, next.Email, next.EmailVerified, next.GivenName, next.FamilyName))
		if err != nil {
			return wrapWrite(err)
		}
		return audit.Record(ctx, tx, event(tenantID, "user.updated", "user", u.ID, userEventData(u)))
	})
	return u, err
}

// SetStatusAudited changes the status and records user.<status> events.
func (s *Store) SetStatusAudited(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID, st Status) error {
	if err := SetStatusTx(ctx, q, tenantID, userID, st); err != nil {
		return err
	}
	typ := map[Status]string{StatusActive: "user.enabled", StatusDisabled: "user.disabled", StatusLocked: "user.locked"}[st]
	return audit.Record(ctx, q, event(tenantID, typ, "user", userID, map[string]any{"id": userID, "status": st}))
}

func (s *Store) SoftDeleteUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET deleted_at = now(), version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`, tenantID, userID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, event(tenantID, "user.deleted", "user", userID, map[string]any{"id": userID}))
	})
}

// PurgeUser physically deletes a soft-deleted user. Audit logs keep only the
// user ID, never personal data.
func (s *Store) PurgeUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var deleted *time.Time
		err := tx.QueryRow(ctx, `SELECT deleted_at FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if deleted == nil {
			return ErrConflict
		}
		for _, q := range []string{
			`DELETE FROM authorization_codes WHERE tenant_id = $1 AND user_id = $2`,
			`DELETE FROM access_tokens WHERE tenant_id = $1 AND user_id = $2`,
			`DELETE FROM users WHERE tenant_id = $1 AND id = $2`,
		} {
			if _, err := tx.Exec(ctx, q, tenantID, userID); err != nil {
				return err
			}
		}
		return audit.Record(ctx, tx, event(tenantID, "user.purged", "user", userID, map[string]any{"id": userID}))
	})
}

func (s *Store) ListUsers(ctx context.Context, tenantID uuid.UUID, f UserFilter, limit int, cursor string) ([]User, string, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users
		WHERE tenant_id = $1 AND deleted_at IS NULL AND id > $2
		  AND ($3 = '' OR lower(login_id) = lower($3))
		  AND ($4 = '' OR lower(email) = lower($4))
		  AND ($5 = '' OR status = $5)
		ORDER BY id LIMIT $6`, tenantID, after, f.LoginID, f.Email, string(f.Status), limit+1)
	if err != nil {
		return nil, "", err
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
	if err != nil {
		return nil, "", err
	}
	return page(users, limit, func(u User) uuid.UUID { return u.ID })
}

// ---------------------------------------------------------------- pagination

func parseCursor(c string) (uuid.UUID, error) {
	if c == "" {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(c)
	if err != nil {
		return uuid.Nil, ErrInvalidCursor
	}
	return id, nil
}

var ErrInvalidCursor = errors.New("identity: invalid page token")

func page[T any](items []T, limit int, id func(T) uuid.UUID) ([]T, string, error) {
	if len(items) <= limit {
		return items, "", nil
	}
	items = items[:limit]
	return items, id(items[len(items)-1]).String(), nil
}

// ---------------------------------------------------------------- groups

const groupColumns = `id, tenant_id, name, version, created_at, updated_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.TenantID, &g.Name, &g.Version, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, ErrNotFound
	}
	return g, err
}

func (s *Store) CreateGroup(ctx context.Context, tenantID uuid.UUID, name string) (Group, error) {
	var g Group
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		g, err = scanGroup(tx.QueryRow(ctx, `INSERT INTO groups (id, tenant_id, name) VALUES ($1, $2, $3) RETURNING `+groupColumns,
			uuid.New(), tenantID, name))
		if err != nil {
			return wrapWrite(err)
		}
		return audit.Record(ctx, tx, event(tenantID, "group.created", "group", g.ID, map[string]any{"id": g.ID, "name": g.Name}))
	})
	return g, err
}

func (s *Store) GetGroup(ctx context.Context, tenantID, id uuid.UUID) (Group, error) {
	return scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupColumns+` FROM groups WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) UpdateGroup(ctx context.Context, tenantID, id uuid.UUID, expectedVersion int64, name string) (Group, error) {
	var g Group
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		g, err = scanGroup(tx.QueryRow(ctx, `UPDATE groups SET name = $4, version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 AND ($3 = 0 OR version = $3) RETURNING `+groupColumns, tenantID, id, expectedVersion, name))
		if errors.Is(err, ErrNotFound) {
			if _, gerr := s.GetGroup(ctx, tenantID, id); gerr == nil {
				return ErrVersionMismatch
			}
		}
		if err != nil {
			return wrapWrite(err)
		}
		return audit.Record(ctx, tx, event(tenantID, "group.updated", "group", g.ID, map[string]any{"id": g.ID, "name": g.Name}))
	})
	return g, err
}

func (s *Store) DeleteGroup(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.deleteRow(ctx, tenantID, id, `DELETE FROM groups WHERE tenant_id = $1 AND id = $2`, "group.deleted", "group")
}

func (s *Store) ListGroups(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) ([]Group, string, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+groupColumns+` FROM groups WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenantID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	groups, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Group, error) { return scanGroup(r) })
	if err != nil {
		return nil, "", err
	}
	return page(groups, limit, func(g Group) uuid.UUID { return g.ID })
}

func (s *Store) AddGroupMember(ctx context.Context, tenantID, groupID, userID uuid.UUID) error {
	return s.link(ctx, tenantID, `INSERT INTO group_members (tenant_id, group_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		groupID, userID, event(tenantID, "group.member_added", "group", groupID, map[string]any{"group_id": groupID, "user_id": userID}))
}

func (s *Store) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID uuid.UUID) error {
	return s.link(ctx, tenantID, `DELETE FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3`,
		groupID, userID, event(tenantID, "group.member_removed", "group", groupID, map[string]any{"group_id": groupID, "user_id": userID}))
}

func (s *Store) ListGroupMembers(ctx context.Context, tenantID, groupID uuid.UUID, limit int, cursor string) ([]User, string, error) {
	if _, err := s.GetGroup(ctx, tenantID, groupID); err != nil {
		return nil, "", err
	}
	after, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+prefixed("u.", userColumns)+` FROM users u
		JOIN group_members m ON m.user_id = u.id AND m.tenant_id = u.tenant_id
		WHERE u.tenant_id = $1 AND m.group_id = $2 AND u.deleted_at IS NULL AND u.id > $3
		ORDER BY u.id LIMIT $4`, tenantID, groupID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) { return scanUser(r) })
	if err != nil {
		return nil, "", err
	}
	return page(users, limit, func(u User) uuid.UUID { return u.ID })
}

// ---------------------------------------------------------------- roles

const roleColumns = `id, tenant_id, name, description, version, created_at, updated_at`

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.Version, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

func (s *Store) CreateRole(ctx context.Context, tenantID uuid.UUID, name, description string) (Role, error) {
	var r Role
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		r, err = scanRole(tx.QueryRow(ctx, `INSERT INTO roles (id, tenant_id, name, description) VALUES ($1, $2, $3, $4) RETURNING `+roleColumns,
			uuid.New(), tenantID, name, description))
		if err != nil {
			return wrapWrite(err)
		}
		return audit.Record(ctx, tx, event(tenantID, "role.created", "role", r.ID, map[string]any{"id": r.ID, "name": r.Name}))
	})
	return r, err
}

func (s *Store) GetRole(ctx context.Context, tenantID, id uuid.UUID) (Role, error) {
	return scanRole(s.pool.QueryRow(ctx, `SELECT `+roleColumns+` FROM roles WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *Store) UpdateRole(ctx context.Context, tenantID, id uuid.UUID, expectedVersion int64, name, description string) (Role, error) {
	var r Role
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var err error
		r, err = scanRole(tx.QueryRow(ctx, `UPDATE roles SET name = $4, description = $5, version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 AND ($3 = 0 OR version = $3) RETURNING `+roleColumns, tenantID, id, expectedVersion, name, description))
		if errors.Is(err, ErrNotFound) {
			if _, gerr := s.GetRole(ctx, tenantID, id); gerr == nil {
				return ErrVersionMismatch
			}
		}
		if err != nil {
			return wrapWrite(err)
		}
		return audit.Record(ctx, tx, event(tenantID, "role.updated", "role", r.ID, map[string]any{"id": r.ID, "name": r.Name}))
	})
	return r, err
}

func (s *Store) DeleteRole(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.deleteRow(ctx, tenantID, id, `DELETE FROM roles WHERE tenant_id = $1 AND id = $2`, "role.deleted", "role")
}

func (s *Store) ListRoles(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) ([]Role, string, error) {
	after, err := parseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+roleColumns+` FROM roles WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenantID, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	roles, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) { return scanRole(r) })
	if err != nil {
		return nil, "", err
	}
	return page(roles, limit, func(r Role) uuid.UUID { return r.ID })
}

func (s *Store) AssignUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	return s.link(ctx, tenantID, `INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		userID, roleID, event(tenantID, "user.role_assigned", "user", userID, map[string]any{"user_id": userID, "role_id": roleID}))
}

func (s *Store) UnassignUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	return s.link(ctx, tenantID, `DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3`,
		userID, roleID, event(tenantID, "user.role_unassigned", "user", userID, map[string]any{"user_id": userID, "role_id": roleID}))
}

func (s *Store) AssignGroupRole(ctx context.Context, tenantID, groupID, roleID uuid.UUID) error {
	return s.link(ctx, tenantID, `INSERT INTO group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		groupID, roleID, event(tenantID, "group.updated", "group", groupID, map[string]any{"group_id": groupID, "role_assigned": roleID}))
}

func (s *Store) UnassignGroupRole(ctx context.Context, tenantID, groupID, roleID uuid.UUID) error {
	return s.link(ctx, tenantID, `DELETE FROM group_roles WHERE tenant_id = $1 AND group_id = $2 AND role_id = $3`,
		groupID, roleID, event(tenantID, "group.updated", "group", groupID, map[string]any{"group_id": groupID, "role_unassigned": roleID}))
}

// EffectiveRoles returns the sorted names of roles assigned directly or via
// groups.
func (s *Store) EffectiveRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	return EffectiveRolesTx(ctx, s.pool, tenantID, userID)
}

func EffectiveRolesTx(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id AND ur.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND ur.user_id = $2
		UNION
		SELECT r.name FROM roles r
		JOIN group_roles gr ON gr.role_id = r.id AND gr.tenant_id = r.tenant_id
		JOIN group_members gm ON gm.group_id = gr.group_id AND gm.tenant_id = gr.tenant_id
		WHERE r.tenant_id = $1 AND gm.user_id = $2`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// GroupRoles returns the role names assigned to a group.
func (s *Store) GroupRoles(ctx context.Context, tenantID, groupID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.name FROM roles r JOIN group_roles gr ON gr.role_id = r.id AND gr.tenant_id = r.tenant_id
		WHERE r.tenant_id = $1 AND gr.group_id = $2 ORDER BY r.name`, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if names == nil {
		names = []string{}
	}
	return names, err
}

// ---------------------------------------------------------------- helpers

// link runs an insert/delete on a join table. A composite foreign key failure
// means one side does not exist in this tenant.
func (s *Store) link(ctx context.Context, tenantID uuid.UUID, sql string, a, b uuid.UUID, ev audit.Event) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, tenantID, a, b)
		if isFKViolation(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // idempotent
		}
		return audit.Record(ctx, tx, ev)
	})
}

func (s *Store) deleteRow(ctx context.Context, tenantID, id uuid.UUID, sql, eventType, targetType string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit.Record(ctx, tx, event(tenantID, eventType, targetType, id, map[string]any{"id": id}))
	})
}

func prefixed(prefix, columns string) string {
	out := ""
	for i, c := range splitColumns(columns) {
		if i > 0 {
			out += ", "
		}
		out += prefix + c
	}
	return out
}

func splitColumns(columns string) []string {
	var cols []string
	cur := ""
	for _, r := range columns {
		switch r {
		case ',':
			cols = append(cols, cur)
			cur = ""
		case ' ', '\n', '\t':
		default:
			cur += string(r)
		}
	}
	return append(cols, cur)
}
