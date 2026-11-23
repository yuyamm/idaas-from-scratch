// Package web is the browser- and protocol-facing HTTP layer: the login UI
// and the OpenID Connect / OAuth 2.0 endpoints.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/mail"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"login", "mfa", "mfa_setup", "recovery_codes", "consent", "message", "forgot", "reset", "account", "passkey"} {
		pages[name] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
}

const (
	sessionCookie = "idaas_session"
	flowCookie    = "idaas_flow"
	csrfCookie    = "idaas_csrf"
)

// Extension lets other modules (federation, passkeys) add routes and login
// options to the UI.
type Extension interface {
	Routes(mux *http.ServeMux, s *Server)
}

// LoginProvider is an external IdP button on the login page.
type LoginProvider struct {
	ID   string
	Name string
}

type Server struct {
	ids       *identity.Store
	authn     *authn.Service
	provider  *oidc.Provider
	enc       crypto.Encrypter
	mailer    mail.Sender
	base      string
	ipLimit   *limiter
	acctLimit *limiter
	// Providers lists external IdPs for the login page.
	Providers func(ctx context.Context, tenant identity.Tenant) []LoginProvider
}

func NewServer(ids *identity.Store, an *authn.Service, p *oidc.Provider, enc crypto.Encrypter, m mail.Sender, baseURL string) *Server {
	return &Server{
		ids: ids, authn: an, provider: p, enc: enc, mailer: m, base: strings.TrimRight(baseURL, "/"),
		ipLimit:   newLimiter(rate.Every(time.Second), 30),
		acctLimit: newLimiter(rate.Every(6*time.Second), 10),
	}
}

func (s *Server) Identity() *identity.Store   { return s.ids }
func (s *Server) Authn() *authn.Service       { return s.authn }
func (s *Server) Provider() *oidc.Provider    { return s.provider }
func (s *Server) BaseURL() string             { return s.base }
func (s *Server) Encrypter() crypto.Encrypter { return s.enc }

// Routes registers the UI and protocol endpoints under /t/{tenant}/.
func (s *Server) Routes(mux *http.ServeMux, extensions ...Extension) {
	t := func(pattern string, h func(http.ResponseWriter, *http.Request, identity.Tenant)) {
		method, path, _ := strings.Cut(pattern, " ")
		mux.Handle(method+" /t/{tenant}"+path, s.withTenant(h))
	}
	// Protocol endpoints.
	t("GET /.well-known/openid-configuration", s.discovery)
	t("GET /jwks", s.jwks)
	t("GET /authorize", s.authorize)
	t("POST /authorize", s.authorize)
	t("POST /token", s.token)
	t("GET /userinfo", s.userinfo)
	t("POST /userinfo", s.userinfo)
	t("POST /introspect", s.introspect)
	t("POST /revoke", s.revoke)
	t("GET /logout", s.logout)
	t("POST /logout", s.logout)
	t("OPTIONS /", s.preflight)
	// UI.
	t("GET /login", s.loginPage)
	t("POST /login", s.loginSubmit)
	t("GET /mfa", s.mfaPage)
	t("POST /mfa", s.mfaSubmit)
	t("GET /mfa/setup", s.mfaSetupPage)
	t("POST /mfa/setup", s.mfaSetupSubmit)
	t("POST /mfa/continue", s.mfaContinue)
	t("GET /consent", s.consentPage)
	t("POST /consent", s.consentSubmit)
	t("GET /forgot", s.forgotPage)
	t("POST /forgot", s.forgotSubmit)
	t("GET /reset", s.resetPage)
	t("POST /reset", s.resetSubmit)
	t("GET /verify-email", s.verifyEmail)
	t("GET /account", s.accountPage)
	t("POST /account/verify-email", s.accountVerifyEmail)
	t("POST /account/totp", s.accountTOTP)
	for _, e := range extensions {
		e.Routes(mux, s)
	}
}

// Tenant registers a tenant-scoped route for extensions.
func (s *Server) Tenant(mux *http.ServeMux, pattern string, h func(http.ResponseWriter, *http.Request, identity.Tenant)) {
	method, path, _ := strings.Cut(pattern, " ")
	mux.Handle(method+" /t/{tenant}"+path, s.withTenant(h))
}

func (s *Server) withTenant(h func(http.ResponseWriter, *http.Request, identity.Tenant)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tn, err := s.ids.GetTenantBySlug(r.Context(), r.PathValue("tenant"))
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		h(w, r, tn)
	})
}

// Middleware applies security headers and records request metadata for audit.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action *")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		ctx := audit.WithRequest(r.Context(), audit.Request{IP: clientIP(r), UserAgent: r.UserAgent()})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "internal error", "path", r.URL.Path, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// ---------------------------------------------------------------- rendering

type view struct {
	Title      string
	TenantName string
	Base       string
	CSRF       string
	ReturnTo   string
	Error      string
	Info       string
	Data       any
}

func (s *Server) tenantBase(t identity.Tenant) string { return "/t/" + t.Slug }

func (s *Server) render(w http.ResponseWriter, r *http.Request, t identity.Tenant, status int, page string, v view) {
	v.TenantName, v.Base, v.CSRF = t.Name, s.tenantBase(t), s.csrfToken(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages[page].ExecuteTemplate(w, page+".html", v); err != nil {
		slog.Error("render", "page", page, "err", err)
	}
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, t identity.Tenant, status int, title, msg string) {
	s.render(w, r, t, status, "message", view{Title: title, Data: map[string]string{"Message": msg}})
}

// ---------------------------------------------------------------- CSRF

// csrfToken returns the double-submit token, setting the cookie if needed.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := secret.NewToken()
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	return tok
}

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf_token"))) == 1
}

// ---------------------------------------------------------------- sealed cookies

// seal encrypts v for a cookie, bound to purpose and tenant.
func (s *Server) seal(purpose string, t identity.Tenant, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	ct, keyID, err := s.enc.Encrypt(raw, []byte(purpose+":"+t.ID.String()))
	if err != nil {
		return "", err
	}
	return keyID + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

func (s *Server) open(purpose string, t identity.Tenant, sealed string, v any) error {
	keyID, b64, ok := strings.Cut(sealed, ".")
	if !ok {
		return errors.New("web: malformed sealed value")
	}
	ct, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	raw, err := s.enc.Decrypt(ct, keyID, []byte(purpose+":"+t.ID.String()))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Server) setCookie(w http.ResponseWriter, t identity.Tenant, name, value string, maxAge time.Duration) {
	c := &http.Cookie{Name: name, Value: value, Path: s.tenantBase(t), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
	if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	}
	if value == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// ---------------------------------------------------------------- sessions

// CurrentSession returns the session from the cookie, if valid.
func (s *Server) CurrentSession(r *http.Request, t identity.Tenant) (authn.Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return authn.Session{}, false
	}
	sess, err := s.authn.LookupSession(r.Context(), t, c.Value)
	if err != nil {
		return authn.Session{}, false
	}
	u, err := s.ids.GetUser(r.Context(), t.ID, sess.UserID)
	if err != nil || u.Status != identity.StatusActive {
		return authn.Session{}, false
	}
	return sess, true
}

// CompleteLogin starts a fresh session (session fixation defense) and
// redirects to returnTo.
func (s *Server) CompleteLogin(w http.ResponseWriter, r *http.Request, t identity.Tenant, userID uuid.UUID, acr string, amr []string, returnTo string) {
	redirect, err := s.startSession(w, r, t, userID, acr, amr, returnTo)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// startSession revokes any current session, creates a new one, sets the
// cookie and returns the safe redirect target.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, t identity.Tenant, userID uuid.UUID, acr string, amr []string, returnTo string) (string, error) {
	ctx := r.Context()
	if old, ok := s.CurrentSession(r, t); ok {
		s.authn.RevokeSession(ctx, t.ID, old.ID)
	}
	raw, _, err := s.authn.CreateSession(ctx, t, userID, acr, amr)
	if err != nil {
		return "", err
	}
	if err := s.authn.RecordLoginSuccess(ctx, t.ID, userID, amr); err != nil {
		return "", err
	}
	s.setCookie(w, t, sessionCookie, raw, 0)
	s.setCookie(w, t, flowCookie, "", 0)
	return s.safeReturnTo(t, returnTo), nil
}

// safeReturnTo only allows relative paths inside the tenant (no open redirect).
func (s *Server) safeReturnTo(t identity.Tenant, returnTo string) string {
	base := s.tenantBase(t) + "/"
	u, err := url.Parse(returnTo)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, base) || strings.Contains(u.Path, "..") {
		return s.tenantBase(t) + "/account"
	}
	return u.RequestURI()
}

// ---------------------------------------------------------------- rate limiting

type limiter struct {
	mu    sync.Mutex
	every rate.Limit
	burst int
	m     map[string]*entry
}

type entry struct {
	l    *rate.Limiter
	seen time.Time
}

func newLimiter(every rate.Limit, burst int) *limiter {
	return &limiter{every: every, burst: burst, m: map[string]*entry{}}
}

func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 10000 {
		for k, e := range l.m {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(l.m, k)
			}
		}
	}
	e, ok := l.m[key]
	if !ok {
		e = &entry{l: rate.NewLimiter(l.every, l.burst)}
		l.m[key] = e
	}
	e.seen = now
	return e.l.Allow()
}

func (s *Server) allowIP(r *http.Request, t identity.Tenant) bool {
	return s.ipLimit.Allow(t.ID.String() + "|" + clientIP(r))
}

func (s *Server) allowAccount(t identity.Tenant, loginID string) bool {
	return s.acctLimit.Allow(t.ID.String() + "|" + strings.ToLower(loginID))
}

func tooMany(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	http.Error(w, "too many requests", http.StatusTooManyRequests)
}

// Seal and Open expose sealed cookies to extensions.
func (s *Server) Seal(purpose string, t identity.Tenant, v any) (string, error) {
	return s.seal(purpose, t, v)
}

func (s *Server) Open(purpose string, t identity.Tenant, sealed string, v any) error {
	return s.open(purpose, t, sealed, v)
}

func (s *Server) SetCookie(w http.ResponseWriter, t identity.Tenant, name, value string, maxAge time.Duration) {
	s.setCookie(w, t, name, value, maxAge)
}

func (s *Server) Message(w http.ResponseWriter, r *http.Request, t identity.Tenant, status int, title, msg string) {
	s.message(w, r, t, status, title, msg)
}

func (s *Server) MessageWithLink(w http.ResponseWriter, r *http.Request, t identity.Tenant, status int, title, msg, link, linkText string) {
	s.render(w, r, t, status, "message", view{Title: title, Data: map[string]string{"Message": msg, "Link": link, "LinkText": linkText}})
}

func (s *Server) CheckCSRF(r *http.Request) bool { return s.checkCSRF(r) }

func (s *Server) TenantBase(t identity.Tenant) string { return s.tenantBase(t) }

func (s *Server) SafeReturnTo(t identity.Tenant, rt string) string { return s.safeReturnTo(t, rt) }

func (s *Server) InternalError(w http.ResponseWriter, r *http.Request, err error) {
	s.internalError(w, r, err)
}
