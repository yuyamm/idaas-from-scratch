package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

func (a *adminClient) scim(method, path string, body any) apiResp {
	a.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.h.issuer()+"/scim/v2"+path, r)
	req.Header.Set("Content-Type", "application/scim+json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
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

// Requirement: users and groups are provisioned with SCIM 2.0 (RFC 7644).
func TestE2E_SCIMProvisioning(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	a := h.admin()
	anon := &adminClient{t: t, h: h}
	anon.must(401, anon.scim("GET", "/Users", nil))

	u := a.must(201, a.scim("POST", "/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "grace", "name": map[string]any{"givenName": "Grace", "familyName": "Hopper"},
		"emails": []map[string]any{{"value": "grace@example.com", "primary": true}}, "active": true,
	}))
	uid := u.body["id"].(string)
	if u.body["meta"].(map[string]any)["resourceType"] != "User" {
		t.Fatalf("user = %s", u.raw)
	}
	a.must(409, a.scim("POST", "/Users", map[string]any{"userName": "grace", "emails": []map[string]any{{"value": "g2@example.com"}}}))

	list := a.must(200, a.scim("GET", "/Users?filter="+url.QueryEscape(`userName eq "grace"`), nil))
	if list.body["totalResults"].(float64) != 1 {
		t.Fatalf("list = %s", list.raw)
	}

	// Deactivate with PATCH: the user can no longer log in.
	p := a.must(200, a.scim("PATCH", "/Users/"+uid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}))
	if p.body["active"] != false {
		t.Fatalf("patched = %s", p.raw)
	}

	g := a.must(201, a.scim("POST", "/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "engineers",
		"members": []map[string]any{{"value": uid}},
	}))
	gid := g.body["id"].(string)
	got := a.must(200, a.scim("GET", "/Groups/"+gid, nil))
	if m, _ := got.body["members"].([]any); len(m) != 1 {
		t.Fatalf("group = %s", got.raw)
	}
	a.must(200, a.scim("PATCH", "/Groups/"+gid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + uid + `"]`}},
	}))
	got = a.must(200, a.scim("GET", "/Groups/"+gid, nil))
	if m, _ := got.body["members"].([]any); len(m) != 0 {
		t.Fatalf("after remove = %s", got.raw)
	}

	a.must(204, a.scim("DELETE", "/Users/"+uid, nil))
	a.must(404, a.scim("GET", "/Users/"+uid, nil))
}
