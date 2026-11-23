package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

type adminClient struct {
	t     *testing.T
	h     *harness
	token string
}

func (h *harness) admin(scopes ...string) *adminClient {
	h.t.Helper()
	id, secret, err := h.app.Bootstrap(context.Background())
	if err != nil {
		h.t.Fatalf("Bootstrap: %v", err)
	}
	if len(scopes) == 0 {
		scopes = []string{"admin:read", "admin:write", "admin:audit:read"}
	}
	cfg := clientcredentials.Config{ClientID: id, ClientSecret: secret, TokenURL: h.base + "/t/admin/token", Scopes: scopes}
	tok, err := cfg.Token(context.WithValue(context.Background(), oauth2.HTTPClient, h.httpClient()))
	if err != nil {
		h.t.Fatalf("admin token: %v", err)
	}
	return &adminClient{t: h.t, h: h, token: tok.AccessToken}
}

type apiResp struct {
	status int
	etag   string
	body   map[string]any
	raw    string
}

func (a *adminClient) call(method, path string, body any, headers ...string) apiResp {
	a.t.Helper()
	var r io.Reader
	ct := "application/json"
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
		if method == http.MethodPatch {
			ct = "application/merge-patch+json"
		}
	}
	req, _ := http.NewRequest(method, a.h.base+"/admin/v1"+path, r)
	if body != nil {
		req.Header.Set("Content-Type", ct)
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := a.h.httpClient().Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := apiResp{status: resp.StatusCode, etag: resp.Header.Get("ETag"), raw: string(raw)}
	json.Unmarshal(raw, &out.body)
	return out
}

func (a *adminClient) must(status int, r apiResp) apiResp {
	a.t.Helper()
	if r.status != status {
		a.t.Fatalf("status = %d, want %d: %s", r.status, status, r.raw)
	}
	return r
}

// Requirement: the Admin API manages tenants, users, groups, roles and
// clients; reads of a single resource are strongly consistent and updates use
// optimistic locking.
func TestE2E_AdminAPIManagesUsersGroupsRoles(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	a := h.admin()

	tn := a.must(201, a.call("POST", "/tenants", map[string]any{"slug": "acme-" + h.tenant.Slug[2:], "name": "Acme"}))
	tid := tn.body["id"].(string)
	if tn.body["issuer"] != h.base+"/t/"+tn.body["slug"].(string) {
		t.Fatalf("tenant = %v", tn.body)
	}

	u := a.must(201, a.call("POST", "/tenants/"+tid+"/users", map[string]any{"user_name": "alice", "email": "alice@example.com", "password": password}))
	uid := u.body["id"].(string)
	a.must(409, a.call("POST", "/tenants/"+tid+"/users", map[string]any{"user_name": "alice", "email": "other@example.com"}))

	got := a.must(200, a.call("GET", "/tenants/"+tid+"/users/"+uid, nil))
	if got.etag == "" || got.body["user_name"] != "alice" {
		t.Fatalf("get = %v etag=%q", got.body, got.etag)
	}
	upd := a.must(200, a.call("PATCH", "/tenants/"+tid+"/users/"+uid, map[string]any{"name": map[string]any{"given_name": "Alice"}}, "If-Match", got.etag))
	a.must(412, a.call("PATCH", "/tenants/"+tid+"/users/"+uid, map[string]any{"name": map[string]any{"given_name": "Stale"}}, "If-Match", got.etag))
	if upd.body["name"].(map[string]any)["given_name"] != "Alice" {
		t.Fatalf("update = %v", upd.body)
	}

	role := a.must(201, a.call("POST", "/tenants/"+tid+"/roles", map[string]any{"name": "billing:admin"}))
	group := a.must(201, a.call("POST", "/tenants/"+tid+"/groups", map[string]any{"name": "finance"}))
	gid, rid := group.body["id"].(string), role.body["id"].(string)
	a.must(204, a.call("PUT", "/tenants/"+tid+"/groups/"+gid+"/members/"+uid, nil))
	a.must(204, a.call("PUT", "/tenants/"+tid+"/groups/"+gid+"/roles/"+rid, nil))
	got = a.must(200, a.call("GET", "/tenants/"+tid+"/users/"+uid, nil))
	if roles, _ := got.body["roles"].([]any); len(roles) != 1 || roles[0] != "billing:admin" {
		t.Fatalf("effective roles = %v", got.body["roles"])
	}
	members := a.must(200, a.call("GET", "/tenants/"+tid+"/groups/"+gid+"/members", nil))
	if items, _ := members.body["items"].([]any); len(items) != 1 {
		t.Fatalf("members = %v", members.body)
	}

	list := a.must(200, a.call("GET", "/tenants/"+tid+"/users?user_name=alice", nil))
	if items, _ := list.body["items"].([]any); len(items) != 1 {
		t.Fatalf("list = %v", list.body)
	}

	// Cross-tenant access is impossible: the user does not exist in another tenant.
	a.must(404, a.call("GET", "/tenants/"+h.tenant.ID.String()+"/users/"+uid, nil))

	a.must(204, a.call("DELETE", "/tenants/"+tid+"/users/"+uid, nil))
	a.must(404, a.call("GET", "/tenants/"+tid+"/users/"+uid, nil))
	a.must(204, a.call("POST", "/tenants/"+tid+"/users/"+uid+"/purge", nil))
}

// Requirement: disabling a user revokes their sessions and tokens.
func TestE2E_AdminDisableUserRevokesTokens(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(b)
	res := r.finish(t, passwordLogin(b, p, "alice"), verifier)

	a := h.admin()
	users := a.must(200, a.call("GET", "/tenants/"+h.tenant.ID.String()+"/users?user_name=alice", nil))
	uid := users.body["items"].([]any)[0].(map[string]any)["id"].(string)
	disabled := a.must(200, a.call("POST", "/tenants/"+h.tenant.ID.String()+"/users/"+uid+"/disable", nil))
	if disabled.body["status"] != "disabled" {
		t.Fatalf("status = %v", disabled.body["status"])
	}
	if _, err := r.provider.UserInfo(r.ctx, oauth2.StaticTokenSource(res.token)); err == nil {
		t.Fatal("access token of a disabled user must be rejected")
	}
	p, _, _ = r.authorize(b)
	if !strings.Contains(p.url.Path, "/login") {
		t.Fatal("session of a disabled user must be revoked")
	}
}

// Requirement: clients are registered through the API; the secret is shown
// once and can be rotated.
func TestE2E_AdminClientsAndSecretRotation(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	a := h.admin()
	tid := h.tenant.ID.String()
	c := a.must(201, a.call("POST", "/tenants/"+tid+"/clients", map[string]any{
		"name": "svc", "client_type": "confidential", "grant_types": []string{"client_credentials"}, "allowed_scopes": []string{"api"}}))
	cid, clientID, first := c.body["id"].(string), c.body["client_id"].(string), c.body["client_secret"].(string)
	if first == "" {
		t.Fatal("client_secret must be returned on creation")
	}
	if got := a.must(200, a.call("GET", "/tenants/"+tid+"/clients/"+cid, nil)); got.body["client_secret"] != nil {
		t.Fatal("client_secret must never be returned again")
	}
	second := a.must(201, a.call("POST", "/tenants/"+tid+"/clients/"+cid+"/secrets", map[string]any{}))
	for _, s := range []string{first, second.body["secret"].(string)} {
		if status, _ := postForm(t, h.httpClient(), h.issuer()+"/token", clientID, s, map[string][]string{"grant_type": {"client_credentials"}}); status != 200 {
			t.Fatalf("secret rotation: token status %d", status)
		}
	}
}

// Requirement: every change is recorded in the audit log (who, when, what,
// from where, result) and delivered to webhooks.
func TestE2E_AuditLogRecordsChanges(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	a := h.admin()
	tid := h.tenant.ID.String()
	u := a.must(201, a.call("POST", "/tenants/"+tid+"/users", map[string]any{"user_name": "carol", "email": "carol@example.com"}))
	for {
		n, err := h.app.Relay().ProcessBatch(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	logs := a.must(200, a.call("GET", "/tenants/"+tid+"/audit-logs?action=user.created", nil))
	items, _ := logs.body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("audit logs = %s", logs.raw)
	}
	l := items[0].(map[string]any)
	actor := l["actor"].(map[string]any)
	if actor["type"] != "admin" || l["ip"] == "" || l["result"] != "success" || l["target"].(map[string]any)["id"] != u.body["id"] {
		t.Fatalf("audit log = %v", l)
	}
}

// Requirement: the Admin API requires a token with the right scope.
func TestE2E_AdminAPIAuthorization(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	anon := &adminClient{t: t, h: h}
	anon.must(401, anon.call("GET", "/tenants", nil))
	ro := h.admin("admin:read")
	ro.must(200, ro.call("GET", "/tenants", nil))
	ro.must(403, ro.call("POST", "/tenants", map[string]any{"slug": "x-" + h.tenant.Slug[2:], "name": "X"}))
	ro.must(403, ro.call("GET", "/tenants/"+h.tenant.ID.String()+"/audit-logs", nil))
}

// Requirement: signing keys rotate without breaking existing tokens.
func TestE2E_AdminRotatesSigningKeys(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	c, secret := h.client(oidcClientForRP())
	r := newRP(t, h, c, secret)
	b := newBrowser(t, h.httpClient(), rpCallback)
	p, verifier, _ := r.authorize(b)
	before := r.finish(t, passwordLogin(b, p, "alice"), verifier)

	a := h.admin()
	keys := a.must(200, a.call("POST", "/tenants/"+h.tenant.ID.String()+"/signing-keys/rotate", nil))
	if items, _ := keys.body["items"].([]any); len(items) != 3 {
		t.Fatalf("keys after rotation = %v", keys.body)
	}
	// A fresh verifier (new JWKS fetch) still accepts the old ID token.
	if _, err := newRP(t, h, c, secret).verifier.Verify(r.ctx, before.raw); err != nil {
		t.Fatalf("old ID token after rotation: %v", err)
	}
	p, verifier, _ = r.authorize(b)
	after := r.finish(t, p, verifier)
	if strings.Split(after.raw, ".")[0] == strings.Split(before.raw, ".")[0] {
		t.Fatal("new tokens must use the new key (different kid header)")
	}
}
