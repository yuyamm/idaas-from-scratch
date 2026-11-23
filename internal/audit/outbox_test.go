package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

func countEvents(t *testing.T, tenantID any, typ string) int {
	t.Helper()
	var n int
	err := pgtest.Pool(t).QueryRow(context.Background(),
		`SELECT count(*) FROM outbox_events WHERE tenant_id = $1 AND event_type = $2`, tenantID, typ).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRecord_WritesEventWithRequestMetadata(t *testing.T) {
	tn := testutil.NewTenant(t, identity.Settings{})
	ctx := audit.WithRequest(context.Background(), audit.Request{IP: "203.0.113.7", UserAgent: "test-agent"})
	ctx = audit.WithActor(ctx, audit.Actor{Type: audit.ActorAdmin, ID: "admin-1"})

	err := audit.Record(ctx, pgtest.Pool(t), audit.Event{
		TenantID: tn.ID, Type: "user.created", TargetType: "user", TargetID: "u-1",
		Data: map[string]any{"login_id": "alice"},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	var ip, ua, actorType, actorID, result string
	err = pgtest.Pool(t).QueryRow(context.Background(),
		`SELECT ip, user_agent, actor_type, actor_id, result FROM outbox_events WHERE tenant_id = $1`, tn.ID).
		Scan(&ip, &ua, &actorType, &actorID, &result)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.7" || ua != "test-agent" || actorType != "admin" || actorID != "admin-1" || result != "success" {
		t.Fatalf("got ip=%s ua=%s actor=%s/%s result=%s", ip, ua, actorType, actorID, result)
	}
}

func TestRecord_RolledBackWithItsTransaction(t *testing.T) {
	tn := testutil.NewTenant(t, identity.Settings{})
	boom := errors.New("boom")

	err := postgres.InTx(context.Background(), pgtest.Pool(t), func(tx pgx.Tx) error {
		if err := audit.Record(context.Background(), tx, audit.Event{TenantID: tn.ID, Type: "user.created", TargetType: "user", TargetID: "x"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if n := countEvents(t, tn.ID, "user.created"); n != 0 {
		t.Fatalf("event must be rolled back with the state change, found %d", n)
	}
}
