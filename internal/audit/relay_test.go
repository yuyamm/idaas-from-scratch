package audit_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

func newRelay(t *testing.T) (*audit.Relay, *audit.WebhookStore, *clock) {
	enc, _ := crypto.NewAESGCM("k", map[string][]byte{"k": make([]byte, 32)})
	c := &clock{t: time.Now().UTC()}
	pool := pgtest.Pool(t)
	ws := audit.NewWebhookStore(pool, enc)
	return audit.NewRelay(pool, ws, audit.WithRelayClock(c.Now)), ws, c
}

func record(t *testing.T, tenantID uuid.UUID, typ string) {
	t.Helper()
	if err := audit.Record(context.Background(), pgtest.Pool(t), audit.Event{TenantID: tenantID, Type: typ, TargetType: "user", TargetID: "u1", Data: map[string]any{"id": "u1"}}); err != nil {
		t.Fatal(err)
	}
}

func drain(t *testing.T, r *audit.Relay) {
	t.Helper()
	for {
		n, err := r.ProcessBatch(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func TestRelay_AppendsAuditLogsAsHashChain(t *testing.T) {
	r, _, _ := newRelay(t)
	tn := testutil.NewTenant(t, identity.Settings{})
	record(t, tn.ID, "user.created")
	record(t, tn.ID, "user.updated")
	drain(t, r)
	drain(t, r) // idempotent

	logs, _, err := r.ListAuditLogs(context.Background(), tn.ID, audit.LogFilter{}, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("want 2 audit logs, got %d", len(logs))
	}
	if ok, err := r.VerifyChain(context.Background(), tn.ID); err != nil || !ok {
		t.Fatalf("VerifyChain = %v, %v", ok, err)
	}
}

func TestAuditLogs_AreAppendOnly(t *testing.T) {
	r, _, _ := newRelay(t)
	tn := testutil.NewTenant(t, identity.Settings{})
	record(t, tn.ID, "user.created")
	drain(t, r)
	_, err := pgtest.Pool(t).Exec(context.Background(), `UPDATE audit_logs SET action = 'x' WHERE tenant_id = $1`, tn.ID)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update must be rejected, err = %v", err)
	}
}

func TestWebhook_DeliversSignedEventsToSubscribers(t *testing.T) {
	r, ws, _ := newRelay(t)
	tn := testutil.NewTenant(t, identity.Settings{})
	type delivery struct {
		body []byte
		sig  string
		id   string
	}
	got := make(chan delivery, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- delivery{b, req.Header.Get("IdaaS-Signature"), req.Header.Get("IdaaS-Event-Id")}
	}))
	defer srv.Close()
	ep, secret, err := ws.Create(context.Background(), tn.ID, srv.URL, []string{"user.created"})
	if err != nil || ep.ID == uuid.Nil || secret == "" {
		t.Fatalf("Create = %+v, %q, %v", ep, secret, err)
	}

	record(t, tn.ID, "user.created")
	record(t, tn.ID, "user.updated") // not subscribed
	drain(t, r)
	if err := r.DeliverDue(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case d := <-got:
		var ev map[string]any
		json.Unmarshal(d.body, &ev)
		if ev["type"] != "user.created" || ev["id"] != d.id || ev["tenant_id"] != tn.ID.String() {
			t.Fatalf("event = %v", ev)
		}
		ts, v1, _ := strings.Cut(strings.TrimPrefix(d.sig, "t="), ",v1=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "." + string(d.body)))
		if hex.EncodeToString(mac.Sum(nil)) != v1 {
			t.Fatalf("bad signature %q", d.sig)
		}
	default:
		t.Fatal("no delivery")
	}
	select {
	case d := <-got:
		t.Fatalf("unsubscribed event delivered: %s", d.body)
	default:
	}
}

func TestWebhook_RetriesWithBackoff(t *testing.T) {
	r, ws, c := newRelay(t)
	tn := testutil.NewTenant(t, identity.Settings{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	ws.Create(context.Background(), tn.ID, srv.URL, []string{"user.created"})
	record(t, tn.ID, "user.created")
	drain(t, r)

	r.DeliverDue(context.Background())
	r.DeliverDue(context.Background()) // not due yet
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 before the backoff elapses", calls.Load())
	}
	c.t = c.t.Add(time.Minute)
	r.DeliverDue(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want a retry after the backoff", calls.Load())
	}
}
