// Package audit records domain events to the transactional outbox and turns
// them into audit logs and webhook deliveries.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorAdmin  ActorType = "admin"
	ActorClient ActorType = "client"
	ActorSystem ActorType = "system"
)

type Actor struct {
	Type ActorType
	ID   string
}

// Request is where the action came from.
type Request struct {
	IP        string
	UserAgent string
}

type Result string

const (
	Success Result = "success"
	Failure Result = "failure"
)

// Event is a domain event. Record writes it to outbox_events; the relay later
// appends it to audit_logs and delivers it to webhooks.
type Event struct {
	TenantID   uuid.UUID
	Type       string
	TargetType string
	TargetID   string
	Data       any
	Result     Result // defaults to Success
	// Actor overrides the actor taken from the context.
	Actor *Actor
}

type ctxKey int

const (
	requestKey ctxKey = iota
	actorKey
)

func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey, r)
}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey, a)
}

func RequestFrom(ctx context.Context) Request {
	r, _ := ctx.Value(requestKey).(Request)
	return r
}

func ActorFrom(ctx context.Context) Actor {
	a, ok := ctx.Value(actorKey).(Actor)
	if !ok {
		return Actor{Type: ActorSystem}
	}
	return a
}

// Record writes e to the outbox using q. Pass the transaction that performs
// the state change so both commit or roll back together.
func Record(ctx context.Context, q postgres.Querier, e Event) error {
	actor := ActorFrom(ctx)
	if e.Actor != nil {
		actor = *e.Actor
	}
	if e.Result == "" {
		e.Result = Success
	}
	data := e.Data
	if data == nil {
		data = map[string]any{}
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("audit: marshal payload: %w", err)
	}
	req := RequestFrom(ctx)
	var actorID *string
	if actor.ID != "" {
		actorID = &actor.ID
	}
	_, err = q.Exec(ctx, `
		INSERT INTO outbox_events (id, tenant_id, event_type, aggregate_type, aggregate_id, payload,
			actor_type, actor_id, result, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		uuid.New(), e.TenantID, e.Type, e.TargetType, e.TargetID, payload,
		string(actor.Type), actorID, string(e.Result), req.IP, req.UserAgent)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Type, err)
	}
	return nil
}
