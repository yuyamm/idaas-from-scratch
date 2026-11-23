package identity_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
)

func ptr[T any](v T) *T { return &v }

func TestEffectiveRoles_CombineDirectAndGroupRoles(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)
	u, _ := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com"})
	admin, _ := s.CreateRole(ctx, tn.ID, "admin", "")
	viewer, _ := s.CreateRole(ctx, tn.ID, "viewer", "")
	g, _ := s.CreateGroup(ctx, tn.ID, "ops")

	if err := s.AssignUserRole(ctx, tn.ID, u.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMember(ctx, tn.ID, g.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignGroupRole(ctx, tn.ID, g.ID, viewer.ID); err != nil {
		t.Fatal(err)
	}
	// Assigning twice is idempotent.
	if err := s.AssignUserRole(ctx, tn.ID, u.ID, admin.ID); err != nil {
		t.Fatal(err)
	}

	roles, err := s.EffectiveRoles(ctx, tn.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(roles, []string{"admin", "viewer"}) {
		t.Fatalf("roles = %v", roles)
	}

	s.RemoveGroupMember(ctx, tn.ID, g.ID, u.ID)
	roles, _ = s.EffectiveRoles(ctx, tn.ID, u.ID)
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("after leaving group: roles = %v", roles)
	}
}

func TestAssignRole_AcrossTenantsIsRejected(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	a, b := newTenant(t, s), newTenant(t, s)
	u, _ := s.CreateUser(ctx, a.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com"})
	roleB, _ := s.CreateRole(ctx, b.ID, "admin", "")

	if err := s.AssignUserRole(ctx, a.ID, u.ID, roleB.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("assigning another tenant's role: err = %v, want ErrNotFound", err)
	}
}

func TestUpdateUser_ChangingEmailResetsVerification(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)
	u, _ := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com", EmailVerified: true})

	got, err := s.UpdateUser(ctx, tn.ID, u.ID, u.Version, identity.UserPatch{Email: ptr("new@example.com"), GivenName: ptr("Alice")})
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "new@example.com" || got.EmailVerified || got.GivenName != "Alice" || got.Version != u.Version+1 {
		t.Fatalf("got %+v", got)
	}
}

func TestUpdateUser_RejectsStaleVersion(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)
	u, _ := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com"})
	s.UpdateUser(ctx, tn.ID, u.ID, u.Version, identity.UserPatch{GivenName: ptr("A")})

	if _, err := s.UpdateUser(ctx, tn.ID, u.ID, u.Version, identity.UserPatch{GivenName: ptr("B")}); !errors.Is(err, identity.ErrVersionMismatch) {
		t.Fatalf("err = %v, want ErrVersionMismatch", err)
	}
}

func TestDeleteUser_SoftThenPurge(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)
	u, _ := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com"})

	if err := s.PurgeUser(ctx, tn.ID, u.ID); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("purging an active user: err = %v, want ErrConflict", err)
	}
	if err := s.SoftDeleteUser(ctx, tn.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, tn.ID, u.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("soft-deleted user must be hidden: err = %v", err)
	}
	// The login ID is free again after soft delete.
	if _, err := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "a@example.com"}); err != nil {
		t.Fatalf("re-create after soft delete: %v", err)
	}
	if err := s.PurgeUser(ctx, tn.ID, u.ID); err != nil {
		t.Fatalf("PurgeUser: %v", err)
	}
}

func TestListUsers_Paginates(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)
	for _, id := range []string{"u1", "u2", "u3"} {
		s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: id, Email: id + "@example.com"})
	}

	page1, next, err := s.ListUsers(ctx, tn.ID, identity.UserFilter{}, 2, "")
	if err != nil || len(page1) != 2 || next == "" {
		t.Fatalf("page1 = %d users, next=%q, err=%v", len(page1), next, err)
	}
	page2, next2, err := s.ListUsers(ctx, tn.ID, identity.UserFilter{}, 2, next)
	if err != nil || len(page2) != 1 || next2 != "" {
		t.Fatalf("page2 = %d users, next=%q, err=%v", len(page2), next2, err)
	}
	if page2[0].ID == page1[0].ID || page2[0].ID == page1[1].ID {
		t.Fatal("pages overlap")
	}
	filtered, _, _ := s.ListUsers(ctx, tn.ID, identity.UserFilter{LoginID: "u2"}, 10, "")
	if len(filtered) != 1 || filtered[0].LoginID != "u2" {
		t.Fatalf("filter by login_id: %+v", filtered)
	}
}

func TestGroupAndRole_CRUD(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)

	g, err := s.CreateGroup(ctx, tn.ID, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, tn.ID, "ops"); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate group: err = %v", err)
	}
	g, err = s.UpdateGroup(ctx, tn.ID, g.ID, g.Version, "operations")
	if err != nil || g.Name != "operations" {
		t.Fatalf("UpdateGroup = %+v, %v", g, err)
	}
	if err := s.DeleteGroup(ctx, tn.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetGroup(ctx, tn.ID, g.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted group: err = %v", err)
	}

	r, _ := s.CreateRole(ctx, tn.ID, "admin", "Administrators")
	r, err = s.UpdateRole(ctx, tn.ID, r.ID, r.Version, "admin", "Admins")
	if err != nil || r.Description != "Admins" {
		t.Fatalf("UpdateRole = %+v, %v", r, err)
	}
	roles, _, _ := s.ListRoles(ctx, tn.ID, 10, "")
	if len(roles) != 1 {
		t.Fatalf("ListRoles = %+v", roles)
	}
}

func TestTenant_UpdateWithVersionAndList(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)

	updated, err := s.UpdateTenant(ctx, tn.ID, tn.Version, "Renamed", identity.Settings{MFARequired: true})
	if err != nil || updated.Name != "Renamed" || !updated.Settings.MFARequired || updated.Version != tn.Version+1 {
		t.Fatalf("UpdateTenant = %+v, %v", updated, err)
	}
	if _, err := s.UpdateTenant(ctx, tn.ID, tn.Version, "Stale", identity.Settings{}); !errors.Is(err, identity.ErrVersionMismatch) {
		t.Fatalf("stale update: err = %v", err)
	}
	all, _, err := s.ListTenants(ctx, 1000, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range all {
		found = found || x.ID == tn.ID
	}
	if !found {
		t.Fatal("ListTenants must include the tenant")
	}
}
