package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

// ---------------------------------------------------------------- webhook endpoints

var ErrNotFound = errors.New("audit: not found")

type WebhookEndpoint struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	URL        string
	EventTypes []string
	Enabled    bool
	CreatedAt  time.Time
}

type WebhookStore struct {
	pool *pgxpool.Pool
	enc  crypto.Encrypter
}

func NewWebhookStore(pool *pgxpool.Pool, enc crypto.Encrypter) *WebhookStore {
	return &WebhookStore{pool: pool, enc: enc}
}

func webhookAAD(tenantID, id uuid.UUID) []byte {
	return []byte("webhook:" + tenantID.String() + ":" + id.String())
}

// Create registers an endpoint and returns its signing secret (shown once).
func (s *WebhookStore) Create(ctx context.Context, tenantID uuid.UUID, url string, eventTypes []string) (WebhookEndpoint, string, error) {
	id := uuid.New()
	plain := secret.NewToken()
	ct, keyID, err := s.enc.Encrypt([]byte(plain), webhookAAD(tenantID, id))
	if err != nil {
		return WebhookEndpoint{}, "", err
	}
	ep := WebhookEndpoint{ID: id, TenantID: tenantID, URL: url, EventTypes: eventTypes, Enabled: true}
	err = s.pool.QueryRow(ctx, `INSERT INTO webhook_endpoints (id, tenant_id, url, secret_encrypted, encryption_key_id, event_types)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at`, id, tenantID, url, ct, keyID, eventTypes).Scan(&ep.CreatedAt)
	return ep, plain, err
}

const webhookColumns = `id, tenant_id, url, event_types, enabled, created_at`

func scanEndpoint(r pgx.Row) (WebhookEndpoint, error) {
	var e WebhookEndpoint
	err := r.Scan(&e.ID, &e.TenantID, &e.URL, &e.EventTypes, &e.Enabled, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

func (s *WebhookStore) Get(ctx context.Context, tenantID, id uuid.UUID) (WebhookEndpoint, error) {
	return scanEndpoint(s.pool.QueryRow(ctx, `SELECT `+webhookColumns+` FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2`, tenantID, id))
}

func (s *WebhookStore) List(ctx context.Context, tenantID uuid.UUID) ([]WebhookEndpoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+webhookColumns+` FROM webhook_endpoints WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (WebhookEndpoint, error) { return scanEndpoint(r) })
}

func (s *WebhookStore) Update(ctx context.Context, tenantID, id uuid.UUID, url *string, eventTypes *[]string, enabled *bool) (WebhookEndpoint, error) {
	return scanEndpoint(s.pool.QueryRow(ctx, `UPDATE webhook_endpoints SET
		url = COALESCE($3, url), event_types = COALESCE($4, event_types), enabled = COALESCE($5, enabled)
		WHERE tenant_id = $1 AND id = $2 RETURNING `+webhookColumns, tenantID, id, url, eventTypes, enabled))
}

func (s *WebhookStore) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *WebhookStore) secret(ctx context.Context, tenantID, id uuid.UUID) ([]byte, error) {
	var ct []byte
	var keyID string
	if err := s.pool.QueryRow(ctx, `SELECT secret_encrypted, encryption_key_id FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&ct, &keyID); err != nil {
		return nil, err
	}
	return s.enc.Decrypt(ct, keyID, webhookAAD(tenantID, id))
}

// ---------------------------------------------------------------- relay

// Relay moves outbox events into the audit log and schedules webhook
// deliveries. It runs as a goroutine inside the server.
type Relay struct {
	pool     *pgxpool.Pool
	webhooks *WebhookStore
	http     *http.Client
	now      func() time.Time
}

type RelayOption func(*Relay)

func WithRelayClock(now func() time.Time) RelayOption { return func(r *Relay) { r.now = now } }

func NewRelay(pool *pgxpool.Pool, ws *WebhookStore, opts ...RelayOption) *Relay {
	r := &Relay{pool: pool, webhooks: ws, http: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run processes the outbox and webhook deliveries until ctx is done.
func (r *Relay) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for {
			n, err := r.ProcessBatch(ctx, 100)
			if err != nil {
				slog.Error("outbox relay", "err", err)
			}
			if n == 0 || err != nil {
				break
			}
		}
		if err := r.DeliverDue(ctx); err != nil {
			slog.Error("webhook delivery", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type outboxRow struct {
	id                        uuid.UUID
	tenantID                  uuid.UUID
	eventType, aggType, aggID string
	payload                   []byte
	actorType                 string
	actorID                   *string
	result, ip, ua            string
	occurredAt                time.Time
}

// ProcessBatch handles up to limit unprocessed events and returns how many.
func (r *Relay) ProcessBatch(ctx context.Context, limit int) (int, error) {
	var n int
	err := postgres.InTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, event_type, aggregate_type, aggregate_id, payload, actor_type, actor_id,
			result, ip, user_agent, occurred_at FROM outbox_events WHERE processed_at IS NULL
			ORDER BY occurred_at, id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
		if err != nil {
			return err
		}
		events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (outboxRow, error) {
			var e outboxRow
			return e, row.Scan(&e.id, &e.tenantID, &e.eventType, &e.aggType, &e.aggID, &e.payload, &e.actorType, &e.actorID,
				&e.result, &e.ip, &e.ua, &e.occurredAt)
		})
		if err != nil {
			return err
		}
		for _, e := range events {
			if err := r.appendLog(ctx, tx, e); err != nil {
				return err
			}
			if err := r.schedule(ctx, tx, e); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE outbox_events SET processed_at = $2 WHERE id = $1`, e.id, r.now().UTC()); err != nil {
				return err
			}
		}
		n = len(events)
		return nil
	})
	return n, err
}

func chainHash(prev []byte, e outboxRow) []byte {
	h := sha256.New()
	h.Write(prev)
	actorID := ""
	if e.actorID != nil {
		actorID = *e.actorID
	}
	for _, f := range []string{e.id.String(), e.tenantID.String(), e.occurredAt.UTC().Format(time.RFC3339Nano), e.actorType, actorID,
		e.eventType, e.aggType, e.aggID, e.result, e.ip, e.ua, string(e.payload)} {
		h.Write([]byte(strconv.Itoa(len(f)) + ":" + f))
	}
	return h.Sum(nil)
}

func (r *Relay) appendLog(ctx context.Context, tx pgx.Tx, e outboxRow) error {
	// Serialize appends per tenant so the chain is linear.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, "audit:"+e.tenantID.String()); err != nil {
		return err
	}
	prev := make([]byte, sha256.Size)
	err := tx.QueryRow(ctx, `SELECT hash FROM audit_logs WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, e.tenantID).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs (tenant_id, event_id, occurred_at, actor_type, actor_id, action, target_type, target_id,
		result, ip, user_agent, details, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (event_id) DO NOTHING`,
		e.tenantID, e.id, e.occurredAt, e.actorType, e.actorID, e.eventType, e.aggType, e.aggID, e.result, e.ip, e.ua, e.payload,
		prev, chainHash(prev, e))
	return err
}

func (r *Relay) schedule(ctx context.Context, tx pgx.Tx, e outboxRow) error {
	_, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, event_id, next_attempt_at)
		SELECT gen_random_uuid(), tenant_id, id, $2, $3 FROM webhook_endpoints
		WHERE tenant_id = $1 AND enabled AND $4 = ANY (event_types)
		ON CONFLICT (endpoint_id, event_id) DO NOTHING`, e.tenantID, e.id, r.now().UTC(), e.eventType)
	return err
}

// VerifyChain recomputes the hash chain of a tenant's audit log.
func (r *Relay) VerifyChain(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	rows, err := r.pool.Query(ctx, `SELECT event_id, tenant_id, occurred_at, actor_type, actor_id, action, target_type, target_id,
		result, ip, user_agent, details, prev_hash, hash FROM audit_logs WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	prev := make([]byte, sha256.Size)
	for rows.Next() {
		var e outboxRow
		var rowPrev, rowHash []byte
		var details []byte
		if err := rows.Scan(&e.id, &e.tenantID, &e.occurredAt, &e.actorType, &e.actorID, &e.eventType, &e.aggType, &e.aggID,
			&e.result, &e.ip, &e.ua, &details, &rowPrev, &rowHash); err != nil {
			return false, err
		}
		e.payload = details
		if !bytes.Equal(rowPrev, prev) || !bytes.Equal(rowHash, chainHash(prev, e)) {
			return false, nil
		}
		prev = rowHash
	}
	return true, rows.Err()
}

// ---------------------------------------------------------------- delivery

const maxAttempts = 8

func backoff(attempts int) time.Duration {
	return time.Duration(math.Pow(2, float64(attempts-1))) * 30 * time.Second
}

// DeliverDue sends pending webhook deliveries whose retry time has come.
func (r *Relay) DeliverDue(ctx context.Context) error {
	type due struct {
		id, tenantID, endpointID uuid.UUID
		attempts                 int
		url                      string
		e                        outboxRow
	}
	rows, err := r.pool.Query(ctx, `SELECT d.id, d.tenant_id, d.endpoint_id, d.attempts, w.url,
		o.id, o.event_type, o.payload, o.actor_type, o.actor_id, o.occurred_at
		FROM webhook_deliveries d
		JOIN webhook_endpoints w ON w.id = d.endpoint_id AND w.tenant_id = d.tenant_id
		JOIN outbox_events o ON o.id = d.event_id
		WHERE d.status = 'pending' AND d.next_attempt_at <= $1 ORDER BY d.next_attempt_at LIMIT 100`, r.now().UTC())
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (due, error) {
		var d due
		return d, row.Scan(&d.id, &d.tenantID, &d.endpointID, &d.attempts, &d.url,
			&d.e.id, &d.e.eventType, &d.e.payload, &d.e.actorType, &d.e.actorID, &d.e.occurredAt)
	})
	if err != nil {
		return err
	}
	for _, d := range list {
		code := r.send(ctx, d.tenantID, d.endpointID, d.url, d.e)
		attempts := d.attempts + 1
		status, next := "pending", r.now().UTC().Add(backoff(attempts))
		switch {
		case code >= 200 && code < 300:
			status = "succeeded"
		case attempts >= maxAttempts:
			status = "failed"
		}
		if _, err := r.pool.Exec(ctx, `UPDATE webhook_deliveries SET status = $2, attempts = $3, next_attempt_at = $4, last_status_code = $5 WHERE id = $1`,
			d.id, status, attempts, next, code); err != nil {
			return err
		}
	}
	return nil
}

func (r *Relay) send(ctx context.Context, tenantID, endpointID uuid.UUID, url string, e outboxRow) int {
	key, err := r.webhooks.secret(ctx, tenantID, endpointID)
	if err != nil {
		return 0
	}
	actor := map[string]any{"type": e.actorType, "id": e.actorID}
	body, _ := json.Marshal(map[string]any{
		"id": e.id, "type": e.eventType, "tenant_id": tenantID, "occurred_at": e.occurredAt.UTC().Format(time.RFC3339Nano),
		"actor": actor, "data": json.RawMessage(e.payload),
	})
	ts := strconv.FormatInt(r.now().Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "." + string(body)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("IdaaS-Event-Id", e.id.String())
	req.Header.Set("IdaaS-Signature", fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))))
	resp, err := r.http.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------- audit log queries

type AuditLog struct {
	Seq        int64
	EventID    uuid.UUID
	OccurredAt time.Time
	ActorType  string
	ActorID    *string
	Action     string
	TargetType string
	TargetID   string
	Result     string
	IP         string
	UserAgent  string
	Details    map[string]any
}

type LogFilter struct {
	From, To *time.Time
	ActorID  string
	Action   string
	Result   string
}

func (r *Relay) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, f LogFilter, limit int, cursor string) ([]AuditLog, string, error) {
	var after int64
	if cursor != "" {
		var err error
		if after, err = strconv.ParseInt(cursor, 10, 64); err != nil {
			return nil, "", err
		}
	}
	rows, err := r.pool.Query(ctx, `SELECT seq, event_id, occurred_at, actor_type, actor_id, action, target_type, target_id, result, ip, user_agent, details
		FROM audit_logs WHERE tenant_id = $1 AND seq > $2
		  AND ($3::timestamptz IS NULL OR occurred_at >= $3) AND ($4::timestamptz IS NULL OR occurred_at < $4)
		  AND ($5 = '' OR actor_id = $5) AND ($6 = '' OR action = $6) AND ($7 = '' OR result = $7)
		ORDER BY seq LIMIT $8`, tenantID, after, f.From, f.To, f.ActorID, f.Action, f.Result, limit+1)
	if err != nil {
		return nil, "", err
	}
	logs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuditLog, error) {
		var l AuditLog
		var details []byte
		if err := row.Scan(&l.Seq, &l.EventID, &l.OccurredAt, &l.ActorType, &l.ActorID, &l.Action, &l.TargetType, &l.TargetID,
			&l.Result, &l.IP, &l.UserAgent, &details); err != nil {
			return l, err
		}
		return l, json.Unmarshal(details, &l.Details)
	})
	if err != nil {
		return nil, "", err
	}
	if len(logs) > limit {
		logs = logs[:limit]
		return logs, strconv.FormatInt(logs[len(logs)-1].Seq, 10), nil
	}
	return logs, "", nil
}
