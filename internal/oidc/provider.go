package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/keys"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

// SupportedScopes are the scopes this provider understands. Client-specific
// scopes (for example API scopes used with client_credentials) are allowed
// through the client's allowed_scopes.
var SupportedScopes = []string{"openid", "profile", "email", "offline_access"}

var ErrInvalidToken = errors.New("oidc: invalid token")

// AuthorizeError is an error at the authorization endpoint. Errors that are
// not Redirectable must be shown to the user instead of redirecting, because
// the client or redirect URI could not be trusted.
type AuthorizeError struct {
	Code         string
	Description  string
	Redirectable bool
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

// TokenError is an RFC 6749 §5.2 error.
type TokenError struct {
	Code        string
	Description string
}

func (e *TokenError) Error() string { return e.Code + ": " + e.Description }

func (e *TokenError) Status() int {
	if e.Code == "invalid_client" {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

func tokenErr(code, desc string) *TokenError { return &TokenError{Code: code, Description: desc} }

type AuthorizeRequest struct {
	Client        Client
	RedirectURI   string
	Scopes        []string
	State         string
	Nonce         string
	CodeChallenge string
	Prompt        []string
	MaxAge        *int
	ACRValues     []string
	LoginHint     string
}

func (r AuthorizeRequest) HasPrompt(p string) bool { return slices.Contains(r.Prompt, p) }

// WantsMFA reports whether the RP asked for MFA via acr_values.
func (r AuthorizeRequest) WantsMFA() bool { return slices.Contains(r.ACRValues, authn.ACRMFA) }

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type Provider struct {
	pool    *pgxpool.Pool
	base    string
	ids     *identity.Store
	clients *ClientStore
	keys    *keys.Service
	authn   *authn.Service
	now     func() time.Time
	http    *http.Client
}

type Option func(*Provider)

func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

func WithHTTPClient(c *http.Client) Option { return func(p *Provider) { p.http = c } }

// NewProvider creates the provider. baseURL is the public origin; each
// tenant's issuer is baseURL + "/t/" + slug.
func NewProvider(pool *pgxpool.Pool, baseURL string, ids *identity.Store, clients *ClientStore, ks *keys.Service, an *authn.Service, opts ...Option) *Provider {
	p := &Provider{pool: pool, base: strings.TrimRight(baseURL, "/"), ids: ids, clients: clients, keys: ks, authn: an,
		now: time.Now, http: &http.Client{Timeout: 5 * time.Second}}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Provider) Keys() *keys.Service             { return p.keys }
func (p *Provider) Clients() *ClientStore           { return p.clients }
func (p *Provider) Now() time.Time                  { return p.now().UTC() }
func (p *Provider) Issuer(t identity.Tenant) string { return p.base + "/t/" + t.Slug }

// ---------------------------------------------------------------- authorize

// ParseAuthorizeRequest validates an authorization request
// (RFC 6749 §4.1.1, OIDC Core §3.1.2.1, RFC 7636).
func (p *Provider) ParseAuthorizeRequest(ctx context.Context, tenant identity.Tenant, v url.Values) (AuthorizeRequest, error) {
	c, err := p.clients.GetByClientID(ctx, tenant.ID, v.Get("client_id"))
	if errors.Is(err, ErrClientNotFound) {
		return AuthorizeRequest{}, &AuthorizeError{Code: "invalid_request", Description: "unknown client_id"}
	}
	if err != nil {
		return AuthorizeRequest{}, err
	}
	redirectURI := v.Get("redirect_uri")
	if redirectURI == "" && len(c.RedirectURIs) == 1 {
		redirectURI = c.RedirectURIs[0]
	}
	if !slices.Contains(c.RedirectURIs, redirectURI) {
		return AuthorizeRequest{}, &AuthorizeError{Code: "invalid_request", Description: "redirect_uri is not registered for this client"}
	}
	req := AuthorizeRequest{
		Client: c, RedirectURI: redirectURI, State: v.Get("state"), Nonce: v.Get("nonce"),
		CodeChallenge: v.Get("code_challenge"), Prompt: strings.Fields(v.Get("prompt")),
		ACRValues: strings.Fields(v.Get("acr_values")), LoginHint: v.Get("login_hint"),
	}
	fail := func(code, desc string) (AuthorizeRequest, error) {
		return req, &AuthorizeError{Code: code, Description: desc, Redirectable: true}
	}
	if v.Has("request") || v.Has("request_uri") {
		return fail("request_not_supported", "request objects are not supported")
	}
	if v.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}
	if m := v.Get("response_mode"); m != "" && m != "query" {
		return fail("invalid_request", "only response_mode=query is supported")
	}
	if !c.AllowsGrant("authorization_code") {
		return fail("unauthorized_client", "client may not use the authorization code grant")
	}
	switch {
	case req.CodeChallenge == "" && c.Type == Public:
		return fail("invalid_request", "public clients must use PKCE")
	case req.CodeChallenge != "" && v.Get("code_challenge_method") != "S256":
		return fail("invalid_request", "code_challenge_method must be S256")
	case req.CodeChallenge != "" && (len(req.CodeChallenge) < 43 || len(req.CodeChallenge) > 128):
		return fail("invalid_request", "invalid code_challenge")
	}
	requested := strings.Fields(v.Get("scope"))
	if !slices.Contains(requested, "openid") {
		return fail("invalid_scope", "the openid scope is required")
	}
	for _, s := range requested {
		if slices.Contains(c.AllowedScopes, s) && !slices.Contains(req.Scopes, s) {
			req.Scopes = append(req.Scopes, s)
		}
	}
	if !slices.Contains(req.Scopes, "openid") {
		return fail("invalid_scope", "client may not request the openid scope")
	}
	if ma := v.Get("max_age"); ma != "" {
		n, err := strconv.Atoi(ma)
		if err != nil || n < 0 {
			return fail("invalid_request", "invalid max_age")
		}
		req.MaxAge = &n
	}
	if req.HasPrompt("none") && len(req.Prompt) > 1 {
		return fail("invalid_request", "prompt=none cannot be combined with other values")
	}
	return req, nil
}

// RedirectWithError builds the error redirect for a Redirectable error.
func (p *Provider) RedirectWithError(tenant identity.Tenant, req AuthorizeRequest, code, desc string) string {
	q := url.Values{"error": {code}, "iss": {p.Issuer(tenant)}}
	if desc != "" {
		q.Set("error_description", desc)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	return appendQuery(req.RedirectURI, q)
}

// RedirectWithCode builds the success redirect (with iss, RFC 9207).
func (p *Provider) RedirectWithCode(tenant identity.Tenant, req AuthorizeRequest, code string) string {
	q := url.Values{"code": {code}, "iss": {p.Issuer(tenant)}}
	if req.State != "" {
		q.Set("state", req.State)
	}
	return appendQuery(req.RedirectURI, q)
}

func appendQuery(rawURL string, q url.Values) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	existing := u.Query()
	for k, vs := range q {
		existing[k] = vs
	}
	u.RawQuery = existing.Encode()
	return u.String()
}

func (p *Provider) NeedsConsent(ctx context.Context, tenantID uuid.UUID, c Client, userID uuid.UUID, scopes []string) (bool, error) {
	if c.FirstParty {
		return false, nil
	}
	var granted []string
	err := p.pool.QueryRow(ctx, `SELECT scopes FROM consents WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3`, tenantID, userID, c.ID).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, s := range scopes {
		if !slices.Contains(granted, s) {
			return true, nil
		}
	}
	return false, nil
}

func (p *Provider) GrantConsent(ctx context.Context, tenantID uuid.UUID, c Client, userID uuid.UUID, scopes []string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO consents (tenant_id, user_id, client_id, scopes) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = (SELECT array_agg(DISTINCT s) FROM unnest(consents.scopes || EXCLUDED.scopes) s), granted_at = now()`,
		tenantID, userID, c.ID, scopes)
	return err
}

// IssueCode stores a one-time authorization code bound to the request and the
// authenticated session.
func (p *Provider) IssueCode(ctx context.Context, tenant identity.Tenant, req AuthorizeRequest, sess authn.Session) (string, error) {
	raw := secret.NewToken()
	_, err := p.pool.Exec(ctx, `INSERT INTO authorization_codes (code_hash, tenant_id, grant_id, client_id, user_id, session_id,
		redirect_uri, scopes, nonce, code_challenge, auth_time, acr, amr, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		secret.HashToken(raw), tenant.ID, uuid.New(), req.Client.ID, sess.UserID, sess.ID, req.RedirectURI, req.Scopes,
		req.Nonce, req.CodeChallenge, sess.AuthTime, sess.ACR, sess.AMR, p.Now().Add(tenant.Settings.AuthorizationCodeTTL()))
	return raw, err
}

// ---------------------------------------------------------------- token

// Token handles the token endpoint for an authenticated client.
func (p *Provider) Token(ctx context.Context, tenant identity.Tenant, c Client, form url.Values) (TokenResponse, error) {
	switch gt := form.Get("grant_type"); gt {
	case "authorization_code":
		return p.exchangeCode(ctx, tenant, c, form)
	case "refresh_token":
		return p.refresh(ctx, tenant, c, form)
	case "client_credentials":
		return p.clientCredentials(ctx, tenant, c, form)
	case "":
		return TokenResponse{}, tokenErr("invalid_request", "grant_type is required")
	default:
		return TokenResponse{}, tokenErr("unsupported_grant_type", "unsupported grant_type "+gt)
	}
}

// grant carries what tokens are minted from.
type grant struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	SessionID *uuid.UUID
	Scopes    []string
	AuthTime  time.Time
	ACR       string
	AMR       []string
	Nonce     string
}

func (p *Provider) exchangeCode(ctx context.Context, tenant identity.Tenant, c Client, form url.Values) (TokenResponse, error) {
	if !c.AllowsGrant("authorization_code") {
		return TokenResponse{}, tokenErr("unauthorized_client", "client may not use the authorization code grant")
	}
	var res TokenResponse
	var reused *uuid.UUID
	err := postgres.InTx(ctx, p.pool, func(tx pgx.Tx) error {
		var (
			g                      grant
			clientID, sessionID    uuid.UUID
			redirectURI, challenge string
			expiresAt              time.Time
			consumedAt             *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT grant_id, client_id, user_id, session_id, redirect_uri, scopes, nonce, code_challenge,
			auth_time, acr, amr, expires_at, consumed_at
			FROM authorization_codes WHERE code_hash = $1 AND tenant_id = $2 FOR UPDATE`,
			secret.HashToken(form.Get("code")), tenant.ID).
			Scan(&g.ID, &clientID, &g.UserID, &sessionID, &redirectURI, &g.Scopes, &g.Nonce, &challenge,
				&g.AuthTime, &g.ACR, &g.AMR, &expiresAt, &consumedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return tokenErr("invalid_grant", "unknown authorization code")
		}
		if err != nil {
			return err
		}
		if consumedAt != nil {
			id := g.ID
			reused = &id
			return tokenErr("invalid_grant", "authorization code has already been used")
		}
		if clientID != c.ID {
			return tokenErr("invalid_grant", "authorization code was issued to another client")
		}
		if !p.Now().Before(expiresAt) {
			return tokenErr("invalid_grant", "authorization code has expired")
		}
		if form.Get("redirect_uri") != redirectURI {
			return tokenErr("invalid_grant", "redirect_uri does not match the authorization request")
		}
		verifier := form.Get("code_verifier")
		if challenge != "" {
			sum := sha256.Sum256([]byte(verifier))
			if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) != 1 {
				return tokenErr("invalid_grant", "PKCE verification failed")
			}
		} else if verifier != "" {
			return tokenErr("invalid_grant", "code_verifier sent but no code_challenge was used")
		}
		if _, err := tx.Exec(ctx, `UPDATE authorization_codes SET consumed_at = $2 WHERE code_hash = $1`, secret.HashToken(form.Get("code")), p.Now()); err != nil {
			return err
		}
		g.SessionID = &sessionID
		res, err = p.mint(ctx, tx, tenant, c, g, true)
		return err
	})
	if reused != nil {
		if rerr := p.revokeGrant(ctx, tenant.ID, *reused, "authorization_code_reuse"); rerr != nil {
			return TokenResponse{}, rerr
		}
	}
	return res, err
}

func (p *Provider) refresh(ctx context.Context, tenant identity.Tenant, c Client, form url.Values) (TokenResponse, error) {
	if !c.AllowsGrant("refresh_token") {
		return TokenResponse{}, tokenErr("unauthorized_client", "client may not use refresh tokens")
	}
	var res TokenResponse
	var reused *uuid.UUID
	err := postgres.InTx(ctx, p.pool, func(tx pgx.Tx) error {
		var (
			g                 grant
			id, clientID      uuid.UUID
			expiresAt         time.Time
			usedAt, revokedAt *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT id, grant_id, client_id, user_id, session_id, scopes, auth_time, acr, amr, expires_at, used_at, revoked_at
			FROM refresh_tokens WHERE token_hash = $1 AND tenant_id = $2 FOR UPDATE`,
			secret.HashToken(form.Get("refresh_token")), tenant.ID).
			Scan(&id, &g.ID, &clientID, &g.UserID, &g.SessionID, &g.Scopes, &g.AuthTime, &g.ACR, &g.AMR, &expiresAt, &usedAt, &revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return tokenErr("invalid_grant", "unknown refresh token")
		}
		if err != nil {
			return err
		}
		if clientID != c.ID {
			return tokenErr("invalid_grant", "refresh token was issued to another client")
		}
		if revokedAt != nil {
			return tokenErr("invalid_grant", "refresh token has been revoked")
		}
		if usedAt != nil {
			gid := g.ID
			reused = &gid
			return tokenErr("invalid_grant", "refresh token has already been used")
		}
		if !p.Now().Before(expiresAt) {
			return tokenErr("invalid_grant", "refresh token has expired")
		}
		u, err := identity.GetUserTx(ctx, tx, tenant.ID, g.UserID)
		if err != nil || u.Status != identity.StatusActive {
			return tokenErr("invalid_grant", "user is not active")
		}
		if s := strings.Fields(form.Get("scope")); len(s) > 0 {
			for _, sc := range s {
				if !slices.Contains(g.Scopes, sc) {
					return tokenErr("invalid_scope", "scope exceeds the original grant")
				}
			}
			g.Scopes = s
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1`, id, p.Now()); err != nil {
			return err
		}
		res, err = p.mintWithParent(ctx, tx, tenant, c, g, false, &id)
		return err
	})
	if reused != nil {
		if rerr := p.revokeGrant(ctx, tenant.ID, *reused, "refresh_token_reuse"); rerr != nil {
			return TokenResponse{}, rerr
		}
	}
	return res, err
}

func (p *Provider) clientCredentials(ctx context.Context, tenant identity.Tenant, c Client, form url.Values) (TokenResponse, error) {
	if c.Type != Confidential || !c.AllowsGrant("client_credentials") {
		return TokenResponse{}, tokenErr("unauthorized_client", "client may not use the client credentials grant")
	}
	scopes := strings.Fields(form.Get("scope"))
	if len(scopes) == 0 {
		scopes = slices.DeleteFunc(slices.Clone(c.AllowedScopes), func(s string) bool { return slices.Contains(SupportedScopes, s) })
	}
	for _, s := range scopes {
		if !slices.Contains(c.AllowedScopes, s) || slices.Contains(SupportedScopes, s) {
			return TokenResponse{}, tokenErr("invalid_scope", "scope "+s+" is not allowed for this client")
		}
	}
	var res TokenResponse
	err := postgres.InTx(ctx, p.pool, func(tx pgx.Tx) error {
		at, err := p.accessToken(ctx, tx, tenant, c, nil, nil, scopes, nil)
		if err != nil {
			return err
		}
		res = TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(tenant.Settings.AccessTokenTTL().Seconds()), Scope: strings.Join(scopes, " ")}
		return nil
	})
	return res, err
}

func (p *Provider) mint(ctx context.Context, tx pgx.Tx, tenant identity.Tenant, c Client, g grant, withNonce bool) (TokenResponse, error) {
	return p.mintWithParent(ctx, tx, tenant, c, g, withNonce, nil)
}

func (p *Provider) mintWithParent(ctx context.Context, tx pgx.Tx, tenant identity.Tenant, c Client, g grant, withNonce bool, parent *uuid.UUID) (TokenResponse, error) {
	u, err := identity.GetUserTx(ctx, tx, tenant.ID, g.UserID)
	if err != nil {
		return TokenResponse{}, tokenErr("invalid_grant", "user no longer exists")
	}
	roles, err := identity.EffectiveRolesTx(ctx, tx, tenant.ID, g.UserID)
	if err != nil {
		return TokenResponse{}, err
	}
	at, err := p.accessToken(ctx, tx, tenant, c, &g.ID, &u, g.Scopes, &tokenAuth{g.AuthTime, g.ACR, g.AMR, roles})
	if err != nil {
		return TokenResponse{}, err
	}
	res := TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(tenant.Settings.AccessTokenTTL().Seconds()), Scope: strings.Join(g.Scopes, " ")}

	if slices.Contains(g.Scopes, "openid") {
		now := p.Now()
		claims := map[string]any{
			"iss": p.Issuer(tenant), "sub": u.ID.String(), "aud": c.ClientID,
			"exp": now.Add(tenant.Settings.IDTokenTTL()).Unix(), "iat": now.Unix(),
			"auth_time": g.AuthTime.Unix(), "acr": g.ACR, "amr": g.AMR, "at_hash": halfHash(at), "roles": roles,
		}
		if g.SessionID != nil {
			claims["sid"] = g.SessionID.String()
		}
		if withNonce && g.Nonce != "" {
			claims["nonce"] = g.Nonce
		}
		for k, v := range scopeClaims(u, g.Scopes) {
			claims[k] = v
		}
		if res.IDToken, err = p.keys.SignJWT(ctx, tenant.ID, "JWT", claims); err != nil {
			return TokenResponse{}, err
		}
	}
	if slices.Contains(g.Scopes, "offline_access") && c.AllowsGrant("refresh_token") {
		raw := secret.NewToken()
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, tenant_id, token_hash, grant_id, parent_id, client_id, user_id,
			session_id, scopes, auth_time, acr, amr, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			uuid.New(), tenant.ID, secret.HashToken(raw), g.ID, parent, c.ID, g.UserID, g.SessionID, g.Scopes,
			g.AuthTime, g.ACR, g.AMR, p.Now().Add(tenant.Settings.RefreshTokenTTL())); err != nil {
			return TokenResponse{}, err
		}
		res.RefreshToken = raw
	}
	return res, nil
}

type tokenAuth struct {
	authTime time.Time
	acr      string
	amr      []string
	roles    []string
}

// accessToken issues a JWT (RFC 9068) or opaque access token. Every access
// token is recorded so it can be introspected and revoked.
func (p *Provider) accessToken(ctx context.Context, tx pgx.Tx, tenant identity.Tenant, c Client, grantID *uuid.UUID, u *identity.User, scopes []string, auth *tokenAuth) (string, error) {
	now := p.Now()
	exp := now.Add(tenant.Settings.AccessTokenTTL())
	jti := uuid.NewString()
	var userID *uuid.UUID
	sub := c.ClientID
	if u != nil {
		userID, sub = &u.ID, u.ID.String()
	}
	var token string
	var tokenHash *string
	if c.AccessTokenFormat == "opaque" {
		token = secret.NewToken()
		h := secret.HashToken(token)
		tokenHash = &h
	} else {
		claims := map[string]any{
			"iss": p.Issuer(tenant), "sub": sub, "aud": p.Issuer(tenant), "client_id": c.ClientID,
			"exp": exp.Unix(), "iat": now.Unix(), "jti": jti, "scope": strings.Join(scopes, " "),
		}
		if auth != nil {
			claims["auth_time"], claims["acr"], claims["amr"], claims["roles"] = auth.authTime.Unix(), auth.acr, auth.amr, auth.roles
		}
		var err error
		if token, err = p.keys.SignJWT(ctx, tenant.ID, "at+jwt", claims); err != nil {
			return "", err
		}
	}
	if scopes == nil {
		scopes = []string{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO access_tokens (jti, tenant_id, token_hash, grant_id, client_id, user_id, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, jti, tenant.ID, tokenHash, grantID, c.ID, userID, scopes, exp)
	return token, err
}

func halfHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func scopeClaims(u identity.User, scopes []string) map[string]any {
	m := map[string]any{}
	if slices.Contains(scopes, "profile") {
		m["name"], m["given_name"], m["family_name"] = u.Name(), u.GivenName, u.FamilyName
	}
	if slices.Contains(scopes, "email") {
		m["email"], m["email_verified"] = u.Email, u.EmailVerified
	}
	return m
}

// revokeGrant revokes every refresh and access token of a grant.
func (p *Provider) revokeGrant(ctx context.Context, tenantID, grantID uuid.UUID, reason string) error {
	return postgres.InTx(ctx, p.pool, func(tx pgx.Tx) error {
		now := p.Now()
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND grant_id = $2 AND revoked_at IS NULL`, tenantID, grantID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE access_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND grant_id = $2 AND revoked_at IS NULL`, tenantID, grantID, now); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "grant.revoked", TargetType: "grant", TargetID: grantID.String(),
			Data: map[string]any{"reason": reason}, Actor: &audit.Actor{Type: audit.ActorSystem}})
	})
}

// RevokeUserTokensTx revokes all tokens issued to a user (used when a user is
// disabled or deleted).
func RevokeUserTokensTx(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID) error {
	if _, err := q.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`, tenantID, userID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE access_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`, tenantID, userID)
	return err
}

// ---------------------------------------------------------------- access token resolution

type accessRecord struct {
	JTI       string
	ClientID  uuid.UUID
	UserID    *uuid.UUID
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
}

func (p *Provider) resolveAccessToken(ctx context.Context, tenant identity.Tenant, token string) (accessRecord, error) {
	var where string
	var arg any
	if strings.Count(token, ".") == 2 {
		payload, err := p.keys.Verify(ctx, tenant.ID, token)
		if err != nil {
			return accessRecord{}, ErrInvalidToken
		}
		var claims struct {
			Iss string `json:"iss"`
			JTI string `json:"jti"`
		}
		if json.Unmarshal(payload, &claims) != nil || claims.Iss != p.Issuer(tenant) || claims.JTI == "" {
			return accessRecord{}, ErrInvalidToken
		}
		where, arg = "jti = $2", claims.JTI
	} else {
		where, arg = "token_hash = $2", secret.HashToken(token)
	}
	var r accessRecord
	err := p.pool.QueryRow(ctx, `SELECT jti, client_id, user_id, scopes, expires_at, created_at FROM access_tokens
		WHERE tenant_id = $1 AND `+where+` AND revoked_at IS NULL`, tenant.ID, arg).
		Scan(&r.JTI, &r.ClientID, &r.UserID, &r.Scopes, &r.ExpiresAt, &r.IssuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return accessRecord{}, ErrInvalidToken
	}
	if err != nil {
		return accessRecord{}, err
	}
	if !p.Now().Before(r.ExpiresAt) {
		return accessRecord{}, ErrInvalidToken
	}
	return r, nil
}

// UserInfo returns the claims allowed by the access token's scopes.
func (p *Provider) UserInfo(ctx context.Context, tenant identity.Tenant, token string) (map[string]any, error) {
	r, err := p.resolveAccessToken(ctx, tenant, token)
	if err != nil {
		return nil, err
	}
	if r.UserID == nil || !slices.Contains(r.Scopes, "openid") {
		return nil, ErrInvalidToken
	}
	u, err := p.ids.GetUser(ctx, tenant.ID, *r.UserID)
	if err != nil || u.Status != identity.StatusActive {
		return nil, ErrInvalidToken
	}
	info := scopeClaims(u, r.Scopes)
	info["sub"] = u.ID.String()
	if roles, err := p.ids.EffectiveRoles(ctx, tenant.ID, u.ID); err == nil {
		info["roles"] = roles
	}
	return info, nil
}

// Introspect implements RFC 7662. Any confidential client of the tenant (for
// example a resource server) may introspect access tokens; refresh tokens can
// only be introspected by the client they were issued to.
func (p *Provider) Introspect(ctx context.Context, tenant identity.Tenant, caller Client, token, hint string) map[string]any {
	inactive := map[string]any{"active": false}
	if caller.Type != Confidential || token == "" {
		return inactive
	}
	tryAccess := func() map[string]any {
		r, err := p.resolveAccessToken(ctx, tenant, token)
		if err != nil {
			return nil
		}
		c, err := p.clients.Get(ctx, tenant.ID, r.ClientID)
		if err != nil {
			return nil
		}
		sub := c.ClientID
		if r.UserID != nil {
			sub = r.UserID.String()
		}
		return map[string]any{"active": true, "scope": strings.Join(r.Scopes, " "), "client_id": c.ClientID, "sub": sub,
			"token_type": "Bearer", "exp": r.ExpiresAt.Unix(), "iat": r.IssuedAt.Unix(), "iss": p.Issuer(tenant),
			"aud": p.Issuer(tenant), "jti": r.JTI}
	}
	tryRefresh := func() map[string]any {
		var (
			userID         uuid.UUID
			scopes         []string
			expiresAt, iat time.Time
		)
		err := p.pool.QueryRow(ctx, `SELECT user_id, scopes, expires_at, created_at FROM refresh_tokens
			WHERE tenant_id = $1 AND token_hash = $2 AND client_id = $3 AND revoked_at IS NULL AND used_at IS NULL AND expires_at > $4`,
			tenant.ID, secret.HashToken(token), caller.ID, p.Now()).Scan(&userID, &scopes, &expiresAt, &iat)
		if err != nil {
			return nil
		}
		return map[string]any{"active": true, "scope": strings.Join(scopes, " "), "client_id": caller.ClientID,
			"sub": userID.String(), "token_type": "refresh_token", "exp": expiresAt.Unix(), "iat": iat.Unix(), "iss": p.Issuer(tenant)}
	}
	order := []func() map[string]any{tryAccess, tryRefresh}
	if hint == "refresh_token" {
		order = []func() map[string]any{tryRefresh, tryAccess}
	}
	for _, f := range order {
		if m := f(); m != nil {
			return m
		}
	}
	return inactive
}

// Revoke implements RFC 7009. Revoking a refresh token revokes its whole
// grant. Unknown tokens and other clients' tokens are ignored.
func (p *Provider) Revoke(ctx context.Context, tenant identity.Tenant, caller Client, token, hint string) error {
	var grantID uuid.UUID
	err := p.pool.QueryRow(ctx, `SELECT grant_id FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2 AND client_id = $3`,
		tenant.ID, secret.HashToken(token), caller.ID).Scan(&grantID)
	if err == nil {
		return p.revokeGrant(ctx, tenant.ID, grantID, "revoked_by_client")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	r, err := p.resolveAccessToken(ctx, tenant, token)
	if err != nil || r.ClientID != caller.ID {
		return nil
	}
	_, err = p.pool.Exec(ctx, `UPDATE access_tokens SET revoked_at = $3 WHERE tenant_id = $1 AND jti = $2`, tenant.ID, r.JTI, p.Now())
	return err
}

// ---------------------------------------------------------------- discovery

type Discovery struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ACRValuesSupported                         []string `json:"acr_values_supported"`
	PromptValuesSupported                      []string `json:"prompt_values_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	BackchannelLogoutSupported                 bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported          bool     `json:"backchannel_logout_session_supported"`
}

func (p *Provider) Discovery(t identity.Tenant) Discovery {
	iss := p.Issuer(t)
	return Discovery{
		Issuer: iss, AuthorizationEndpoint: iss + "/authorize", TokenEndpoint: iss + "/token", UserinfoEndpoint: iss + "/userinfo",
		JWKSURI: iss + "/jwks", IntrospectionEndpoint: iss + "/introspect", RevocationEndpoint: iss + "/revoke", EndSessionEndpoint: iss + "/logout",
		ScopesSupported: SupportedScopes, ResponseTypesSupported: []string{"code"}, ResponseModesSupported: []string{"query"},
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"}, SubjectTypesSupported: []string{"public"},
		IDTokenSigningAlgValuesSupported:          []string{keys.Alg},
		TokenEndpointAuthMethodsSupported:         []string{string(ClientSecretBasic), string(ClientSecretPost), string(AuthNone)},
		IntrospectionEndpointAuthMethodsSupported: []string{string(ClientSecretBasic), string(ClientSecretPost)},
		RevocationEndpointAuthMethodsSupported:    []string{string(ClientSecretBasic), string(ClientSecretPost), string(AuthNone)},
		CodeChallengeMethodsSupported:             []string{"S256"},
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "name", "given_name",
			"family_name", "email", "email_verified", "roles"},
		ACRValuesSupported: []string{authn.ACRPassword, authn.ACRMFA}, PromptValuesSupported: []string{"none", "login", "consent"},
		AuthorizationResponseIssParameterSupported: true, BackchannelLogoutSupported: true, BackchannelLogoutSessionSupported: true,
	}
}

// AccessInfo describes a valid access token.
type AccessInfo struct {
	ClientID string
	Scopes   []string
	UserID   *uuid.UUID
}

// AuthenticateBearer validates an access token issued by tenant.
func (p *Provider) AuthenticateBearer(ctx context.Context, tenant identity.Tenant, token string) (AccessInfo, error) {
	r, err := p.resolveAccessToken(ctx, tenant, token)
	if err != nil {
		return AccessInfo{}, err
	}
	c, err := p.clients.Get(ctx, tenant.ID, r.ClientID)
	if err != nil {
		return AccessInfo{}, ErrInvalidToken
	}
	return AccessInfo{ClientID: c.ClientID, Scopes: r.Scopes, UserID: r.UserID}, nil
}
