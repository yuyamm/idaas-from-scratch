// Package pgtest provides a migrated PostgreSQL pool for tests.
//
// Tests share one database. Each test creates its own tenant, so tenant
// isolation also isolates test data.
package pgtest

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

const defaultURL = "postgres://idaas:idaas@localhost:54329/idaas_test?sslmode=disable"

var (
	once    sync.Once
	pool    *pgxpool.Pool
	initErr error
)

// Pool returns a pool connected to the test database with migrations applied.
// Start the database with `docker compose up -d`, or set TEST_DATABASE_URL.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	once.Do(func() {
		url := os.Getenv("TEST_DATABASE_URL")
		if url == "" {
			url = defaultURL
		}
		ctx := context.Background()
		pool, initErr = postgres.Open(ctx, url)
		if initErr == nil {
			initErr = postgres.Migrate(ctx, pool)
		}
	})
	if initErr != nil {
		t.Fatalf("pgtest: %v (is `docker compose up -d` running?)", initErr)
	}
	return pool
}
