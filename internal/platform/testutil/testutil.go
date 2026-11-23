// Package testutil has helpers shared by tests.
package testutil

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
)

// NewTenant creates a tenant with a unique slug.
func NewTenant(t testing.TB, settings identity.Settings) identity.Tenant {
	t.Helper()
	s := identity.NewStore(pgtest.Pool(t))
	tn, err := s.CreateTenantWithSettings(context.Background(), "t-"+uuid.NewString()[:12], "Test", settings)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn
}
