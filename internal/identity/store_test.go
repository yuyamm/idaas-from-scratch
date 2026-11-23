package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
)

func newTenant(t *testing.T, s *identity.Store) identity.Tenant {
	t.Helper()
	tn, err := s.CreateTenant(context.Background(), "t-"+uuid.NewString()[:8], "Test")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return tn
}

func TestStore_CreateUserThenFindByLoginID(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	tn := newTenant(t, s)

	created, err := s.CreateUser(ctx, tn.ID, identity.NewUser{LoginID: "alice", Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == uuid.Nil || created.Status != identity.StatusActive {
		t.Fatalf("unexpected user: %+v", created)
	}

	got, err := s.FindUserByLoginID(ctx, tn.ID, "alice")
	if err != nil {
		t.Fatalf("FindUserByLoginID: %v", err)
	}
	if got.ID != created.ID || got.Email != "alice@example.com" {
		t.Fatalf("got %+v, want %+v", got, created)
	}
}

func TestStore_UserIsInvisibleFromOtherTenant(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	a, b := newTenant(t, s), newTenant(t, s)

	u, err := s.CreateUser(ctx, a.ID, identity.NewUser{LoginID: "bob", Email: "bob@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := s.FindUserByLoginID(ctx, b.ID, "bob"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("FindUserByLoginID from other tenant: err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetUser(ctx, b.ID, u.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("GetUser from other tenant: err = %v, want ErrNotFound", err)
	}
}

func TestStore_LoginIDIsUniquePerTenant(t *testing.T) {
	ctx := context.Background()
	s := identity.NewStore(pgtest.Pool(t))
	a, b := newTenant(t, s), newTenant(t, s)

	if _, err := s.CreateUser(ctx, a.ID, identity.NewUser{LoginID: "carol", Email: "c@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, a.ID, identity.NewUser{LoginID: "carol", Email: "c2@example.com"}); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate login_id in same tenant: err = %v, want ErrConflict", err)
	}
	if _, err := s.CreateUser(ctx, b.ID, identity.NewUser{LoginID: "carol", Email: "c@example.com"}); err != nil {
		t.Fatalf("same login_id in another tenant must be allowed: %v", err)
	}
}
