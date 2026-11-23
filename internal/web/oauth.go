package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
)

func contextWithoutCancel(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// cors allows browser-based (public) clients to call the token-style
// endpoints. These endpoints never rely on cookies.
func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	h.Set("Access-Control-Allow-Methods", "GET, POST")
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request, _ identity.Tenant) {
	cors(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	cors(w)
	writeJSON(w, http.StatusOK, s.provider.Discovery(t))
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	set, err := s.provider.Keys().JWKS(r.Context(), t.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cors(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
}

// ---------------------------------------------------------------- authorize

// withoutParam returns the request URI with one value removed from a
// space-separated parameter (used to drop prompt=login after re-auth).
func withoutParam(u *url.URL, key, value string) string {
	q := u.Query()
	if value == "" {
		q.Del(key)
	} else {
		vals := slices.DeleteFunc(strings.Fields(q.Get(key)), func(v string) bool { return v == value })
		if len(vals) == 0 {
			q.Del(key)
		} else {
			q.Set(key, strings.Join(vals, " "))
		}
	}
	return u.Path + "?" + q.Encode()
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		r.URL.RawQuery = r.PostForm.Encode()
	}
	ctx := r.Context()
	req, err := s.provider.ParseAuthorizeRequest(ctx, t, r.URL.Query())
	var ae *oidc.AuthorizeError
	if errors.As(err, &ae) {
		if !ae.Redirectable {
			s.message(w, r, t, http.StatusBadRequest, "リクエストが不正です", ae.Description)
			return
		}
		http.Redirect(w, r, s.provider.RedirectWithError(t, req, ae.Code, ae.Description), http.StatusFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	self := &url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}

	sess, ok := s.CurrentSession(r, t)
	needLogin := !ok || req.HasPrompt("login") ||
		(req.MaxAge != nil && time.Since(sess.AuthTime) > time.Duration(*req.MaxAge)*time.Second) ||
		(req.WantsMFA() && sess.ACR != "urn:idaas:acr:mfa")
	if needLogin {
		if req.HasPrompt("none") {
			http.Redirect(w, r, s.provider.RedirectWithError(t, req, "login_required", "the user is not logged in"), http.StatusFound)
			return
		}
		q := url.Values{"return_to": {withoutParam(self, "prompt", "login")}}
		if req.LoginHint != "" {
			q.Set("login_hint", req.LoginHint)
		}
		http.Redirect(w, r, s.tenantBase(t)+"/login?"+q.Encode(), http.StatusFound)
		return
	}

	needConsent, err := s.provider.NeedsConsent(ctx, t.ID, req.Client, sess.UserID, req.Scopes)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if needConsent || req.HasPrompt("consent") {
		if req.HasPrompt("none") {
			http.Redirect(w, r, s.provider.RedirectWithError(t, req, "consent_required", "consent is required"), http.StatusFound)
			return
		}
		http.Redirect(w, r, s.tenantBase(t)+"/consent?"+url.Values{"return_to": {withoutParam(self, "prompt", "consent")}}.Encode(), http.StatusFound)
		return
	}

	code, err := s.provider.IssueCode(ctx, t, req, sess)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, s.provider.RedirectWithCode(t, req, code), http.StatusFound)
}

// requestFromReturnTo re-parses the authorization request carried in return_to.
func (s *Server) requestFromReturnTo(r *http.Request, t identity.Tenant, returnTo string) (oidc.AuthorizeRequest, bool) {
	u, err := url.Parse(s.safeReturnTo(t, returnTo))
	if err != nil || u.Path != s.tenantBase(t)+"/authorize" {
		return oidc.AuthorizeRequest{}, false
	}
	req, err := s.provider.ParseAuthorizeRequest(r.Context(), t, u.Query())
	return req, err == nil
}

func (s *Server) consentPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	returnTo := r.URL.Query().Get("return_to")
	req, ok := s.requestFromReturnTo(r, t, returnTo)
	if _, signedIn := s.CurrentSession(r, t); !ok || !signedIn {
		s.message(w, r, t, http.StatusBadRequest, "リクエストが不正です", "同意する対象のリクエストが見つかりません。")
		return
	}
	s.render(w, r, t, http.StatusOK, "consent", view{Title: "アクセスの許可", ReturnTo: returnTo,
		Data: map[string]any{"ClientName": req.Client.Name, "Scopes": req.Scopes}})
}

func (s *Server) consentSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	returnTo := r.PostFormValue("return_to")
	req, ok := s.requestFromReturnTo(r, t, returnTo)
	sess, signedIn := s.CurrentSession(r, t)
	if !ok || !signedIn {
		s.message(w, r, t, http.StatusBadRequest, "リクエストが不正です", "同意する対象のリクエストが見つかりません。")
		return
	}
	if r.PostFormValue("decision") != "allow" {
		http.Redirect(w, r, s.provider.RedirectWithError(t, req, "access_denied", "the user denied the request"), http.StatusFound)
		return
	}
	if err := s.provider.GrantConsent(r.Context(), t.ID, req.Client, sess.UserID, req.Scopes); err != nil {
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, s.safeReturnTo(t, returnTo), http.StatusFound)
}

// ---------------------------------------------------------------- client authentication

func (s *Server) clientCredentials(r *http.Request) (oidc.ClientCredentials, bool, error) {
	if err := r.ParseForm(); err != nil {
		return oidc.ClientCredentials{}, false, err
	}
	formID, formSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if user, pass, ok := r.BasicAuth(); ok {
		if formSecret != "" {
			return oidc.ClientCredentials{}, true, errors.New("multiple client authentication methods")
		}
		// RFC 6749 §2.3.1: credentials are form-urlencoded before Basic encoding.
		id, err1 := url.QueryUnescape(user)
		sec, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return oidc.ClientCredentials{}, true, errors.New("malformed basic credentials")
		}
		return oidc.ClientCredentials{ID: id, Secret: sec, Method: oidc.ClientSecretBasic}, true, nil
	}
	if formSecret != "" {
		return oidc.ClientCredentials{ID: formID, Secret: formSecret, Method: oidc.ClientSecretPost}, false, nil
	}
	return oidc.ClientCredentials{ID: formID, Method: oidc.AuthNone}, false, nil
}

func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request, t identity.Tenant) (oidc.Client, bool) {
	cred, basic, err := s.clientCredentials(r)
	if err == nil && cred.ID != "" {
		c, aerr := s.provider.Clients().Authenticate(r.Context(), t.ID, cred)
		if aerr == nil {
			return c, true
		}
		if !errors.Is(aerr, oidc.ErrClientAuth) {
			s.internalError(w, r, aerr)
			return oidc.Client{}, false
		}
	}
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="idaas"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client authentication failed"})
	return oidc.Client{}, false
}

// ---------------------------------------------------------------- token endpoints

func (s *Server) token(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	cors(w)
	if !s.allowIP(r, t) {
		tooMany(w)
		return
	}
	c, ok := s.authenticateClient(w, r, t)
	if !ok {
		return
	}
	res, err := s.provider.Token(r.Context(), t, c, r.PostForm)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	var te *oidc.TokenError
	if errors.As(err, &te) {
		writeJSON(w, te.Status(), map[string]string{"error": te.Code, "error_description": te.Description})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return r.PostFormValue("access_token")
	}
	return ""
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	cors(w)
	info, err := s.provider.UserInfo(r.Context(), t, bearer(r))
	if errors.Is(err, oidc.ErrInvalidToken) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) introspect(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	c, ok := s.authenticateClient(w, r, t)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.provider.Introspect(r.Context(), t, c, r.PostForm.Get("token"), r.PostForm.Get("token_type_hint")))
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	cors(w)
	c, ok := s.authenticateClient(w, r, t)
	if !ok {
		return
	}
	if r.PostForm.Get("token") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "token is required"})
		return
	}
	if err := s.provider.Revoke(r.Context(), t, c, r.PostForm.Get("token"), r.PostForm.Get("token_type_hint")); err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------- logout

func (s *Server) logout(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	r.ParseForm()
	ctx := r.Context()
	q := r.Form
	if r.Method == http.MethodPost && q.Get("id_token_hint") == "" && q.Get("client_id") == "" && !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var client *oidc.Client
	if hint := q.Get("id_token_hint"); hint != "" {
		h, err := s.provider.ParseIDTokenHint(ctx, t, hint)
		if err != nil {
			s.message(w, r, t, http.StatusBadRequest, "リクエストが不正です", "id_token_hint を検証できません。")
			return
		}
		if c, err := s.provider.Clients().GetByClientID(ctx, t.ID, h.ClientID); err == nil {
			client = &c
		}
	}
	if id := q.Get("client_id"); id != "" {
		c, err := s.provider.Clients().GetByClientID(ctx, t.ID, id)
		if err != nil || (client != nil && client.ID != c.ID) {
			s.message(w, r, t, http.StatusBadRequest, "リクエストが不正です", "client_id が不正です。")
			return
		}
		client = &c
	}
	if sess, ok := s.CurrentSession(r, t); ok {
		if err := s.provider.EndSession(ctx, t, sess.ID); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.setCookie(w, t, sessionCookie, "", 0)
	if target := q.Get("post_logout_redirect_uri"); target != "" && client != nil && s.provider.ValidPostLogoutRedirect(*client, target) {
		if st := q.Get("state"); st != "" {
			target = appendQuery(target, url.Values{"state": {st}})
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	s.message(w, r, t, http.StatusOK, "ログアウトしました", "ログアウトしました。")
}

func appendQuery(raw string, q url.Values) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	existing := u.Query()
	for k, v := range q {
		existing[k] = v
	}
	u.RawQuery = existing.Encode()
	return u.String()
}
