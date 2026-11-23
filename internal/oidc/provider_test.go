package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/keys"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/pgtest"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/testutil"
)

const redirect = "https://app.example/cb"

type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type env struct {
	p       *oidc.Provider
	clients *oidc.ClientStore
	ids     *identity.Store
	authn   *authn.Service
	tenant  identity.Tenant
	user    identity.User
	clock   *clock
}

func newEnv(t *testing.T) env {
	t.Helper()
	pool := pgtest.Pool(t)
	enc, _ := crypto.NewAESGCM("k", map[string][]byte{"k": make([]byte, 32)})
	c := &clock{t: time.Now().UTC().Truncate(time.Second)}
	ids := identity.NewStore(pool)
	an := authn.NewService(pool, authn.NewPasswordHasher(authn.Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}), authn.WithClock(c.Now))
	ks := keys.NewService(pool, enc, keys.WithClock(c.Now))
	cs := oidc.NewClientStore(pool)
	p := oidc.NewProvider(pool, "https://idaas.test", ids, cs, ks, an, oidc.WithClock(c.Now))
	tn := testutil.NewTenant(t, identity.Settings{})
	u, err := ids.CreateUser(context.Background(), tn.ID, identity.NewUser{LoginID: "alice", Email: "alice@example.com", EmailVerified: true, GivenName: "Alice", FamilyName: "Liddell"})
	if err != nil {
		t.Fatal(err)
	}
	return env{p: p, clients: cs, ids: ids, authn: an, tenant: tn, user: u, clock: c}
}

func (e env) client(t *testing.T, nc oidc.NewClient) (oidc.Client, string) {
	t.Helper()
	if nc.Name == "" {
		nc.Name = "app"
	}
	if nc.Type == "" {
		nc.Type = oidc.Confidential
	}
	if nc.GrantTypes == nil {
		nc.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if nc.RedirectURIs == nil {
		nc.RedirectURIs = []string{redirect}
	}
	if nc.AllowedScopes == nil {
		nc.AllowedScopes = []string{"openid", "profile", "email", "offline_access"}
	}
	c, s, err := e.clients.Create(context.Background(), e.tenant.ID, nc)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeParams(c oidc.Client, challenge string, scope string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {c.ClientID}, "redirect_uri": {redirect},
		"scope": {scope}, "state": {"st"}, "nonce": {"n-123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
}

// login runs the authorization step and returns an authorization code.
func (e env) login(t *testing.T, c oidc.Client, scope string) (code, verifier string) {
	t.Helper()
	ctx := context.Background()
	verifier, challenge := pkce()
	req, err := e.p.ParseAuthorizeRequest(ctx, e.tenant, authorizeParams(c, challenge, scope))
	if err != nil {
		t.Fatalf("ParseAuthorizeRequest: %v", err)
	}
	_, sess, err := e.authn.CreateSession(ctx, e.tenant, e.user.ID, authn.ACRMFA, []string{"pwd", "otp"})
	if err != nil {
		t.Fatal(err)
	}
	code, err = e.p.IssueCode(ctx, e.tenant, req, sess)
	if err != nil {
		t.Fatal(err)
	}
	return code, verifier
}

func exchange(e env, c oidc.Client, code, verifier string) (oidc.TokenResponse, error) {
	return e.p.Token(context.Background(), e.tenant, c, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	})
}

func claims(t *testing.T, e env, token string) map[string]any {
	t.Helper()
	payload, err := e.p.Keys().Verify(context.Background(), e.tenant.ID, token)
	if err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
	var m map[string]any
	json.Unmarshal(payload, &m)
	return m
}

func errCode(err error) string {
	var te *oidc.TokenError
	if errors.As(err, &te) {
		return te.Code
	}
	var ae *oidc.AuthorizeError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// ---------------------------------------------------------------- authorize

func TestAuthorize_RejectsWithoutRedirectForUnknownClientOrRedirectURI(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	_, challenge := pkce()

	p := authorizeParams(c, challenge, "openid")
	p.Set("client_id", "unknown")
	var ae *oidc.AuthorizeError
	if _, err := e.p.ParseAuthorizeRequest(context.Background(), e.tenant, p); !errors.As(err, &ae) || ae.Redirectable {
		t.Fatalf("unknown client must not redirect: %v", err)
	}

	p = authorizeParams(c, challenge, "openid")
	p.Set("redirect_uri", redirect+"/extra") // prefix match is not enough
	if _, err := e.p.ParseAuthorizeRequest(context.Background(), e.tenant, p); !errors.As(err, &ae) || ae.Redirectable {
		t.Fatalf("redirect_uri mismatch must not redirect: %v", err)
	}
}

func TestAuthorize_RejectsInvalidRequests(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	spa, _ := e.client(t, oidc.NewClient{Type: oidc.Public})
	_, challenge := pkce()
	cases := []struct {
		name   string
		client oidc.Client
		mutate func(url.Values)
		want   string
	}{
		{"public client without PKCE", spa, func(v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") }, "invalid_request"},
		{"plain PKCE", c, func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"implicit flow", c, func(v url.Values) { v.Set("response_type", "id_token token") }, "unsupported_response_type"},
		{"no openid scope", c, func(v url.Values) { v.Set("scope", "profile") }, "invalid_scope"},
	}
	for _, tc := range cases {
		p := authorizeParams(tc.client, challenge, "openid")
		tc.mutate(p)
		_, err := e.p.ParseAuthorizeRequest(context.Background(), e.tenant, p)
		var ae *oidc.AuthorizeError
		if !errors.As(err, &ae) || !ae.Redirectable || ae.Code != tc.want {
			t.Errorf("%s: err = %v, want redirectable %s", tc.name, err, tc.want)
		}
	}
}

func TestAuthorize_StateAndNonceAreOptionalAndUnknownScopesAreDropped(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	_, challenge := pkce()
	p := authorizeParams(c, challenge, "openid admin email")
	p.Del("state")
	p.Del("nonce")
	req, err := e.p.ParseAuthorizeRequest(context.Background(), e.tenant, p)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(req.Scopes, []string{"openid", "email"}) {
		t.Fatalf("scopes = %v; scopes the client may not request must be dropped", req.Scopes)
	}
}

func TestAuthorize_ConfidentialClientMayOmitPKCE(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	p := authorizeParams(c, "", "openid")
	p.Del("code_challenge")
	p.Del("code_challenge_method")
	req, err := e.p.ParseAuthorizeRequest(context.Background(), e.tenant, p)
	if err != nil {
		t.Fatal(err)
	}
	_, sess, _ := e.authn.CreateSession(context.Background(), e.tenant, e.user.ID, authn.ACRPassword, []string{"pwd"})
	code, _ := e.p.IssueCode(context.Background(), e.tenant, req, sess)
	if _, err := e.p.Token(context.Background(), e.tenant, c, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}}); err != nil {
		t.Fatalf("confidential client without PKCE: %v", err)
	}
}

func TestConsent_SkippedForFirstPartyAndRemembered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	third, _ := e.client(t, oidc.NewClient{})
	first, _ := e.client(t, oidc.NewClient{FirstParty: true})

	if need, _ := e.p.NeedsConsent(ctx, e.tenant.ID, first, e.user.ID, []string{"openid", "email"}); need {
		t.Fatal("first-party clients must not need consent")
	}
	if need, _ := e.p.NeedsConsent(ctx, e.tenant.ID, third, e.user.ID, []string{"openid", "email"}); !need {
		t.Fatal("third-party client needs consent")
	}
	e.p.GrantConsent(ctx, e.tenant.ID, third, e.user.ID, []string{"openid", "email"})
	if need, _ := e.p.NeedsConsent(ctx, e.tenant.ID, third, e.user.ID, []string{"openid"}); need {
		t.Fatal("consent for a subset of granted scopes must be remembered")
	}
	if need, _ := e.p.NeedsConsent(ctx, e.tenant.ID, third, e.user.ID, []string{"openid", "profile"}); !need {
		t.Fatal("new scopes need fresh consent")
	}
}

// ---------------------------------------------------------------- token: authorization_code

func TestToken_AuthorizationCodeIssuesSpecCompliantTokens(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	admin, _ := e.ids.CreateRole(context.Background(), e.tenant.ID, "admin", "")
	e.ids.AssignUserRole(context.Background(), e.tenant.ID, e.user.ID, admin.ID)

	code, verifier := e.login(t, c, "openid profile email offline_access")
	res, err := exchange(e, c, code, verifier)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if res.TokenType != "Bearer" || res.ExpiresIn != 600 || res.RefreshToken == "" || res.IDToken == "" {
		t.Fatalf("response = %+v", res)
	}

	id := claims(t, e, res.IDToken)
	want := map[string]any{
		"iss": "https://idaas.test/t/" + e.tenant.Slug, "sub": e.user.ID.String(), "aud": c.ClientID,
		"nonce": "n-123", "acr": authn.ACRMFA, "email": "alice@example.com", "email_verified": true,
		"name": "Alice Liddell", "given_name": "Alice", "family_name": "Liddell",
	}
	for k, v := range want {
		if id[k] != v {
			t.Errorf("id_token[%s] = %v, want %v", k, id[k], v)
		}
	}
	for _, k := range []string{"exp", "iat", "auth_time", "sid", "at_hash"} {
		if id[k] == nil {
			t.Errorf("id_token missing %s", k)
		}
	}
	if amr, _ := id["amr"].([]any); len(amr) != 2 {
		t.Errorf("amr = %v", id["amr"])
	}
	if roles, _ := id["roles"].([]any); len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v", id["roles"])
	}

	at := claims(t, e, res.AccessToken)
	if at["client_id"] != c.ClientID || at["sub"] != e.user.ID.String() || at["jti"] == nil || at["scope"] != "openid profile email offline_access" {
		t.Errorf("access token claims = %v", at)
	}
}

func TestToken_NoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid")
	res, err := exchange(e, c, code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken != "" {
		t.Fatal("refresh token requires offline_access")
	}
}

func TestToken_RejectsWrongPKCEVerifierRedirectURIOrClient(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	other, _ := e.client(t, oidc.NewClient{})

	code, _ := e.login(t, c, "openid")
	if _, err := exchange(e, c, code, strings.Repeat("x", 43)); errCode(err) != "invalid_grant" {
		t.Fatalf("wrong verifier: %v", err)
	}

	code, verifier := e.login(t, c, "openid")
	_, err := e.p.Token(context.Background(), e.tenant, c, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://evil.example/cb"}, "code_verifier": {verifier}})
	if errCode(err) != "invalid_grant" {
		t.Fatalf("wrong redirect_uri: %v", err)
	}

	code, verifier = e.login(t, c, "openid")
	if _, err := exchange(e, other, code, verifier); errCode(err) != "invalid_grant" {
		t.Fatalf("code issued to another client: %v", err)
	}
}

func TestToken_CodeExpires(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid")
	e.clock.Advance(61 * time.Second)
	if _, err := exchange(e, c, code, verifier); errCode(err) != "invalid_grant" {
		t.Fatalf("expired code: %v", err)
	}
}

func TestToken_CodeReuseRevokesIssuedTokens(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid offline_access")
	first, err := exchange(e, c, code, verifier)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := exchange(e, c, code, verifier); errCode(err) != "invalid_grant" {
		t.Fatalf("reused code: %v", err)
	}
	if got := e.p.Introspect(context.Background(), e.tenant, c, first.AccessToken, ""); got["active"] != false {
		t.Fatalf("access token from a reused code must be revoked: %v", got)
	}
	_, err = e.p.Token(context.Background(), e.tenant, c, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}})
	if errCode(err) != "invalid_grant" {
		t.Fatalf("refresh token from a reused code must be revoked: %v", err)
	}
}

// ---------------------------------------------------------------- token: refresh_token

func refresh(e env, c oidc.Client, rt string) (oidc.TokenResponse, error) {
	return e.p.Token(context.Background(), e.tenant, c, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

func TestRefresh_RotatesToken(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid offline_access")
	first, _ := exchange(e, c, code, verifier)

	second, err := refresh(e, c, first.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.IDToken == "" {
		t.Fatalf("refresh must return a new refresh token and ID token: %+v", second)
	}
	if _, err := refresh(e, c, second.RefreshToken); err != nil {
		t.Fatalf("rotated token must work: %v", err)
	}
}

func TestRefresh_ReuseRevokesWholeFamily(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid offline_access")
	first, _ := exchange(e, c, code, verifier)
	second, _ := refresh(e, c, first.RefreshToken)

	if _, err := refresh(e, c, first.RefreshToken); errCode(err) != "invalid_grant" {
		t.Fatalf("reused refresh token: %v", err)
	}
	if _, err := refresh(e, c, second.RefreshToken); errCode(err) != "invalid_grant" {
		t.Fatalf("legitimate token of a compromised family must be revoked too: %v", err)
	}
	if got := e.p.Introspect(context.Background(), e.tenant, c, second.AccessToken, ""); got["active"] != false {
		t.Fatalf("access tokens of the family must be revoked: %v", got)
	}
}

func TestRefresh_RejectsOtherClient(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	other, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid offline_access")
	first, _ := exchange(e, c, code, verifier)
	if _, err := refresh(e, other, first.RefreshToken); errCode(err) != "invalid_grant" {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------- token: client_credentials

func TestClientCredentials_ConfidentialOnly(t *testing.T) {
	e := newEnv(t)
	m2m, _ := e.client(t, oidc.NewClient{GrantTypes: []string{"client_credentials"}, AllowedScopes: []string{"api:read"}})
	res, err := e.p.Token(context.Background(), e.tenant, m2m, url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken != "" || res.RefreshToken != "" || res.AccessToken == "" {
		t.Fatalf("client_credentials must return only an access token: %+v", res)
	}
	at := claims(t, e, res.AccessToken)
	if at["sub"] != m2m.ClientID || at["scope"] != "api:read" {
		t.Fatalf("claims = %v", at)
	}

	spa, _ := e.client(t, oidc.NewClient{Type: oidc.Public, GrantTypes: []string{"client_credentials"}})
	if _, err := e.p.Token(context.Background(), e.tenant, spa, url.Values{"grant_type": {"client_credentials"}}); errCode(err) != "unauthorized_client" {
		t.Fatalf("public client: %v", err)
	}
	web, _ := e.client(t, oidc.NewClient{})
	if _, err := e.p.Token(context.Background(), e.tenant, web, url.Values{"grant_type": {"client_credentials"}}); errCode(err) != "unauthorized_client" {
		t.Fatalf("grant not registered: %v", err)
	}
}

// ---------------------------------------------------------------- introspect / revoke / userinfo

func TestIntrospect_ResourceServerCanIntrospectOpaqueToken(t *testing.T) {
	e := newEnv(t)
	app, _ := e.client(t, oidc.NewClient{AccessTokenFormat: "opaque"})
	rs, _ := e.client(t, oidc.NewClient{GrantTypes: []string{"client_credentials"}})
	code, verifier := e.login(t, app, "openid")
	res, _ := exchange(e, app, code, verifier)
	if strings.Count(res.AccessToken, ".") == 2 {
		t.Fatal("opaque access token must not be a JWT")
	}

	got := e.p.Introspect(context.Background(), e.tenant, rs, res.AccessToken, "access_token")
	if got["active"] != true || got["client_id"] != app.ClientID || got["sub"] != e.user.ID.String() || got["scope"] != "openid" {
		t.Fatalf("introspection = %v", got)
	}
	if got := e.p.Introspect(context.Background(), e.tenant, rs, "garbage", ""); len(got) != 1 || got["active"] != false {
		t.Fatalf("invalid token must return only active=false: %v", got)
	}
}

func TestRevoke_RefreshTokenRevokesGrant(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid offline_access")
	res, _ := exchange(e, c, code, verifier)

	if err := e.p.Revoke(context.Background(), e.tenant, c, res.RefreshToken, "refresh_token"); err != nil {
		t.Fatal(err)
	}
	if _, err := refresh(e, c, res.RefreshToken); errCode(err) != "invalid_grant" {
		t.Fatalf("revoked refresh token: %v", err)
	}
	if got := e.p.Introspect(context.Background(), e.tenant, c, res.AccessToken, ""); got["active"] != false {
		t.Fatalf("access token of a revoked grant: %v", got)
	}
	if err := e.p.Revoke(context.Background(), e.tenant, c, "unknown-token", ""); err != nil {
		t.Fatalf("revoking an unknown token must succeed: %v", err)
	}
}

func TestRevoke_CannotRevokeOtherClientsToken(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	other, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid")
	res, _ := exchange(e, c, code, verifier)
	e.p.Revoke(context.Background(), e.tenant, other, res.AccessToken, "")
	if got := e.p.Introspect(context.Background(), e.tenant, c, res.AccessToken, ""); got["active"] != true {
		t.Fatal("a client must not revoke another client's token")
	}
}

func TestUserInfo_ReturnsClaimsForGrantedScopes(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid email")
	res, _ := exchange(e, c, code, verifier)

	info, err := e.p.UserInfo(context.Background(), e.tenant, res.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if info["sub"] != e.user.ID.String() || info["email"] != "alice@example.com" {
		t.Fatalf("userinfo = %v", info)
	}
	if _, ok := info["given_name"]; ok {
		t.Fatal("profile claims require the profile scope")
	}
	if _, err := e.p.UserInfo(context.Background(), e.tenant, "garbage"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestTokens_AreRejectedByOtherTenant(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{})
	code, verifier := e.login(t, c, "openid")
	res, _ := exchange(e, c, code, verifier)
	other := testutil.NewTenant(t, identity.Settings{})
	if _, err := e.p.UserInfo(context.Background(), other, res.AccessToken); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscovery_AdvertisesSupportedFeatures(t *testing.T) {
	e := newEnv(t)
	d := e.p.Discovery(e.tenant)
	if d.Issuer != "https://idaas.test/t/"+e.tenant.Slug || d.JWKSURI != d.Issuer+"/jwks" {
		t.Fatalf("discovery = %+v", d)
	}
	if !slices.Equal(d.ResponseTypesSupported, []string{"code"}) || !slices.Equal(d.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Fatalf("discovery = %+v", d)
	}
}
