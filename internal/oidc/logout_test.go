package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

func TestEndSession_SendsBackchannelLogoutAndRevokesSession(t *testing.T) {
	e := newEnv(t)
	got := make(chan string, 1)
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got <- r.PostForm.Get("logout_token")
	}))
	defer rp.Close()
	uri := rp.URL
	c, _ := e.client(t, oidc.NewClient{BackchannelLogoutURI: &uri})
	ctx := context.Background()

	// Log in through the code flow so the session is linked to the client.
	code, verifier := e.login(t, c, "openid")
	res, err := exchange(e, c, code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	hint, err := e.p.ParseIDTokenHint(ctx, e.tenant, res.IDToken)
	if err != nil {
		t.Fatalf("ParseIDTokenHint: %v", err)
	}
	if hint.ClientID != c.ClientID || hint.SessionID == nil {
		t.Fatalf("hint = %+v", hint)
	}

	if err := e.p.EndSession(ctx, e.tenant, *hint.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.authn.GetSession(ctx, e.tenant.ID, *hint.SessionID); err != nil {
		t.Fatal(err)
	}

	select {
	case token := <-got:
		payload, err := e.p.Keys().Verify(ctx, e.tenant.ID, token)
		if err != nil {
			t.Fatalf("logout_token signature: %v", err)
		}
		var claims map[string]any
		json.Unmarshal(payload, &claims)
		events, _ := claims["events"].(map[string]any)
		if claims["sid"] != hint.SessionID.String() || claims["aud"] != c.ClientID || claims["nonce"] != nil ||
			events["http://schemas.openid.net/event/backchannel-logout"] == nil {
			t.Fatalf("logout_token claims = %v", claims)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("back-channel logout was not sent")
	}
}

func TestEndSession_SessionCannotBeUsedAfterwards(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	raw, sess, _ := e.authn.CreateSession(ctx, e.tenant, e.user.ID, authn.ACRPassword, []string{"pwd"})
	if err := e.p.EndSession(ctx, e.tenant, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.authn.LookupSession(ctx, e.tenant, raw); err == nil {
		t.Fatal("session must be revoked")
	}
}

func TestPostLogoutRedirect_RequiresExactMatch(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, oidc.NewClient{PostLogoutRedirectURIs: []string{"https://app.example/bye"}})
	if !e.p.ValidPostLogoutRedirect(c, "https://app.example/bye") {
		t.Fatal("registered URI must be accepted")
	}
	if e.p.ValidPostLogoutRedirect(c, "https://app.example/bye?x=1") {
		t.Fatal("unregistered URI must be rejected")
	}
}
