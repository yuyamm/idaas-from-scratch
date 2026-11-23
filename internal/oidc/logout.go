package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

// IDTokenHint is what we learn from a verified id_token_hint. Expired ID
// tokens are accepted as hints, as RP-Initiated Logout allows.
type IDTokenHint struct {
	ClientID  string
	Subject   string
	SessionID *uuid.UUID
}

func (p *Provider) ParseIDTokenHint(ctx context.Context, tenant identity.Tenant, token string) (IDTokenHint, error) {
	payload, err := p.keys.Verify(ctx, tenant.ID, token)
	if err != nil {
		return IDTokenHint{}, ErrInvalidToken
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Sub string `json:"sub"`
		Sid string `json:"sid"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Iss != p.Issuer(tenant) {
		return IDTokenHint{}, ErrInvalidToken
	}
	h := IDTokenHint{ClientID: claims.Aud, Subject: claims.Sub}
	if sid, err := uuid.Parse(claims.Sid); err == nil {
		h.SessionID = &sid
	}
	return h, nil
}

func (p *Provider) ValidPostLogoutRedirect(c Client, uri string) bool {
	return uri != "" && slices.Contains(c.PostLogoutRedirectURIs, uri)
}

// EndSession revokes an IdP session, revokes refresh tokens bound to it
// (except offline_access ones) and notifies RPs via Back-Channel Logout.
func (p *Provider) EndSession(ctx context.Context, tenant identity.Tenant, sessionID uuid.UUID) error {
	type target struct {
		clientID string
		uri      string
		userID   uuid.UUID
	}
	var targets []target
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var userID uuid.UUID
		err := tx.QueryRow(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, $3) WHERE tenant_id = $1 AND id = $2 RETURNING user_id`,
			tenant.ID, sessionID, p.Now()).Scan(&userID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND session_id = $2
			AND revoked_at IS NULL AND NOT ('offline_access' = ANY (scopes))`, tenant.ID, sessionID, p.Now()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT c.client_id, c.backchannel_logout_uri, ac.user_id
			FROM authorization_codes ac JOIN clients c ON c.id = ac.client_id AND c.tenant_id = ac.tenant_id
			WHERE ac.tenant_id = $1 AND ac.session_id = $2 AND ac.consumed_at IS NOT NULL AND c.backchannel_logout_uri IS NOT NULL`,
			tenant.ID, sessionID)
		if err != nil {
			return err
		}
		targets, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
			var t target
			return t, r.Scan(&t.clientID, &t.uri, &t.userID)
		})
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenant.ID, Type: "user.logout", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"session_id": sessionID}, Actor: &audit.Actor{Type: audit.ActorUser, ID: userID.String()}})
	})
	if err != nil {
		return err
	}
	for _, t := range targets {
		now := p.Now()
		token, err := p.keys.SignJWT(ctx, tenant.ID, "logout+jwt", map[string]any{
			"iss": p.Issuer(tenant), "aud": t.clientID, "sub": t.userID.String(), "sid": sessionID.String(),
			"iat": now.Unix(), "exp": now.Add(2 * 60e9).Unix(), "jti": uuid.NewString(),
			"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
		})
		if err != nil {
			return err
		}
		go p.sendLogoutToken(t.uri, token)
	}
	return nil
}

func (p *Provider) sendLogoutToken(uri, token string) {
	resp, err := p.http.Post(uri, "application/x-www-form-urlencoded", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		slog.Warn("back-channel logout failed", "uri", uri, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		slog.Warn("back-channel logout rejected", "uri", uri, "status", resp.StatusCode)
	}
}
