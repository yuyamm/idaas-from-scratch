package federation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/web"
)

const (
	fedCookie  = "idaas_fed"
	fedPurpose = "federation"
)

// RP logs users in with external OIDC IdPs. IdaaS acts as an OIDC RP here.
type RP struct {
	store *Store
	http  *http.Client
}

func NewRP(store *Store, httpClient *http.Client) *RP { return &RP{store: store, http: httpClient} }

type fedState struct {
	ProviderID uuid.UUID  `json:"p"`
	State      string     `json:"s"`
	Nonce      string     `json:"n"`
	Verifier   string     `json:"v"`
	ReturnTo   string     `json:"rt"`
	LinkUserID *uuid.UUID `json:"link,omitempty"`
	Exp        int64      `json:"exp"`
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (rp *RP) Routes(mux *http.ServeMux, s *web.Server) {
	s.Tenant(mux, "GET /federation/{idp}/start", func(w http.ResponseWriter, r *http.Request, t identity.Tenant) { rp.start(w, r, s, t, nil) })
	s.Tenant(mux, "POST /federation/{idp}/start", func(w http.ResponseWriter, r *http.Request, t identity.Tenant) { rp.start(w, r, s, t, nil) })
	s.Tenant(mux, "POST /federation/{idp}/link", func(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
		sess, ok := s.CurrentSession(r, t)
		if !ok || !s.CheckCSRF(r) {
			http.Redirect(w, r, s.TenantBase(t)+"/login", http.StatusFound)
			return
		}
		rp.start(w, r, s, t, &sess.UserID)
	})
	s.Tenant(mux, "GET /federation/callback", func(w http.ResponseWriter, r *http.Request, t identity.Tenant) { rp.callback(w, r, s, t) })
	s.Providers = func(ctx context.Context, t identity.Tenant) []web.LoginProvider {
		ps, err := rp.store.ListIdPs(ctx, t.ID)
		if err != nil {
			return nil
		}
		out := make([]web.LoginProvider, len(ps))
		for i, p := range ps {
			out[i] = web.LoginProvider{ID: p.ID.String(), Name: p.Name}
		}
		return out
	}
	web.Linked = func(r *http.Request, t identity.Tenant, userID uuid.UUID) []web.LinkedAccount {
		links, err := rp.store.ListLinks(r.Context(), t.ID, userID)
		if err != nil {
			return nil
		}
		return links
	}
}

func (rp *RP) config(ctx context.Context, s *web.Server, t identity.Tenant, p IdentityProvider) (*oauth2.Config, *gooidc.Provider, error) {
	ctx = gooidc.ClientContext(ctx, rp.http)
	provider, err := gooidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, nil, err
	}
	secret, err := rp.store.clientSecret(ctx, t.ID, p.ID)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(), Scopes: p.Scopes,
		RedirectURL: s.BaseURL() + s.TenantBase(t) + "/federation/callback"}, provider, nil
}

func (rp *RP) start(w http.ResponseWriter, r *http.Request, s *web.Server, t identity.Tenant, linkUser *uuid.UUID) {
	id, err := uuid.Parse(r.PathValue("idp"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := rp.store.GetIdP(r.Context(), t.ID, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cfg, _, err := rp.config(r.Context(), s, t, p)
	if err != nil {
		s.Message(w, r, t, http.StatusBadGateway, "外部 IdP に接続できません", "しばらくしてからもう一度お試しください。")
		return
	}
	st := fedState{ProviderID: p.ID, State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(),
		ReturnTo: r.FormValue("return_to"), LinkUserID: linkUser, Exp: time.Now().Add(10 * time.Minute).Unix()}
	sealed, err := s.Seal(fedPurpose, t, st)
	if err != nil {
		s.InternalError(w, r, err)
		return
	}
	s.SetCookie(w, t, fedCookie, sealed, 10*time.Minute)
	http.Redirect(w, r, cfg.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier), gooidc.Nonce(st.Nonce)), http.StatusFound)
}

type externalClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

func (rp *RP) callback(w http.ResponseWriter, r *http.Request, s *web.Server, t identity.Tenant) {
	ctx := r.Context()
	c, err := r.Cookie(fedCookie)
	var st fedState
	if err != nil || s.Open(fedPurpose, t, c.Value, &st) != nil || time.Now().Unix() > st.Exp || r.URL.Query().Get("state") != st.State {
		s.Message(w, r, t, http.StatusBadRequest, "ログインに失敗しました", "リクエストが不正か、有効期限が切れています。")
		return
	}
	s.SetCookie(w, t, fedCookie, "", 0)
	if e := r.URL.Query().Get("error"); e != "" {
		s.Message(w, r, t, http.StatusUnauthorized, "ログインに失敗しました", "外部 IdP でログインできませんでした（"+e+"）。")
		return
	}
	p, err := rp.store.GetIdP(ctx, t.ID, st.ProviderID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cfg, provider, err := rp.config(ctx, s, t, p)
	if err != nil {
		s.Message(w, r, t, http.StatusBadGateway, "外部 IdP に接続できません", "しばらくしてからもう一度お試しください。")
		return
	}
	octx := gooidc.ClientContext(ctx, rp.http)
	tok, err := cfg.Exchange(octx, r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.Message(w, r, t, http.StatusUnauthorized, "ログインに失敗しました", "外部 IdP からトークンを取得できませんでした。")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&gooidc.Config{ClientID: p.ClientID}).Verify(octx, raw)
	if err != nil || idt.Nonce != st.Nonce {
		s.Message(w, r, t, http.StatusUnauthorized, "ログインに失敗しました", "外部 IdP の ID トークンを検証できませんでした。")
		return
	}
	var claims externalClaims
	if err := idt.Claims(&claims); err != nil || claims.Subject == "" {
		s.Message(w, r, t, http.StatusUnauthorized, "ログインに失敗しました", "外部 IdP の ID トークンが不正です。")
		return
	}

	if st.LinkUserID != nil {
		rp.link(w, r, s, t, p, *st.LinkUserID, claims)
		return
	}
	userID, err := rp.store.FindLinkedUser(ctx, t.ID, p.ID, claims.Subject)
	if errors.Is(err, ErrNotFound) {
		userID, err = rp.signup(w, r, s, t, p, claims)
		if err != nil {
			return // response written
		}
	} else if err != nil {
		s.InternalError(w, r, err)
		return
	}
	s.AfterPrimaryAuth(w, r, t, userID, []string{"fed"}, st.ReturnTo)
}

var errHandled = errors.New("federation: response already written")

// signup handles an external account that is not linked yet. A matching
// email alone never merges accounts.
func (rp *RP) signup(w http.ResponseWriter, r *http.Request, s *web.Server, t identity.Tenant, p IdentityProvider, c externalClaims) (uuid.UUID, error) {
	ctx := r.Context()
	ids := identity.NewStore(rp.store.pool)
	if c.Email != "" {
		if _, err := ids.FindUserByEmail(ctx, t.ID, c.Email); err == nil {
			s.MessageWithLink(w, r, t, http.StatusConflict, "既存のアカウントがあります",
				"このメールアドレスの既存のアカウントがあります。既存のアカウントでログインし、アカウント画面から "+p.Name+" と連携してください。",
				s.TenantBase(t)+"/account", "既存のアカウントでログイン")
			return uuid.Nil, errHandled
		}
	}
	if !p.AllowSignup {
		s.Message(w, r, t, http.StatusForbidden, "アカウントが見つかりません", p.Name+" のアカウントに対応するアカウントが見つかりません。管理者に連絡してください。")
		return uuid.Nil, errHandled
	}
	loginID := c.Email
	if loginID == "" {
		loginID = strings.ToLower(p.Name) + ":" + c.Subject
	}
	var userID uuid.UUID
	err := postgres.InTx(ctx, rp.store.pool, func(tx pgx.Tx) error {
		u, err := identity.CreateUserTx(ctx, tx, t.ID, identity.NewUser{LoginID: loginID, Email: c.Email, EmailVerified: c.EmailVerified && c.Email != "",
			GivenName: c.GivenName, FamilyName: c.FamilyName})
		if err != nil {
			return err
		}
		userID = u.ID
		if err := audit.Record(ctx, tx, audit.Event{TenantID: t.ID, Type: "user.created", TargetType: "user", TargetID: u.ID.String(),
			Data: map[string]any{"id": u.ID, "user_name": u.LoginID, "via": p.Name}, Actor: &audit.Actor{Type: audit.ActorUser, ID: u.ID.String()}}); err != nil {
			return err
		}
		return rp.store.linkTx(ctx, tx, t.ID, u.ID, p, c)
	})
	if err != nil {
		if errors.Is(err, identity.ErrConflict) {
			s.Message(w, r, t, http.StatusConflict, "アカウントを作成できません", "このログイン ID はすでに使われています。")
		} else {
			s.InternalError(w, r, err)
		}
		return uuid.Nil, errHandled
	}
	return userID, nil
}

func (rp *RP) link(w http.ResponseWriter, r *http.Request, s *web.Server, t identity.Tenant, p IdentityProvider, userID uuid.UUID, c externalClaims) {
	ctx := r.Context()
	if sess, ok := s.CurrentSession(r, t); !ok || sess.UserID != userID {
		s.Message(w, r, t, http.StatusUnauthorized, "連携できません", "連携を始めたアカウントでログインしたまま操作してください。")
		return
	}
	err := postgres.InTx(ctx, rp.store.pool, func(tx pgx.Tx) error { return rp.store.linkTx(ctx, tx, t.ID, userID, p, c) })
	if errors.Is(err, ErrConflict) {
		s.Message(w, r, t, http.StatusConflict, "連携できません", "この外部アカウントはすでに別のアカウントと連携しています。")
		return
	}
	if err != nil {
		s.InternalError(w, r, err)
		return
	}
	http.Redirect(w, r, s.TenantBase(t)+"/account?linked=1", http.StatusFound)
}

// ---------------------------------------------------------------- links

func (s *Store) linkTx(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, p IdentityProvider, c externalClaims) error {
	_, err := tx.Exec(ctx, `INSERT INTO federated_identities (id, tenant_id, user_id, provider_id, subject, email) VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.New(), tenantID, userID, p.ID, c.Subject, c.Email)
	if postgres.IsUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	return audit.Record(ctx, tx, audit.Event{TenantID: tenantID, Type: "user.federated_identity_linked", TargetType: "user", TargetID: userID.String(),
		Data: map[string]any{"provider": p.Name, "subject": c.Subject}, Actor: &audit.Actor{Type: audit.ActorUser, ID: userID.String()}})
}

func (s *Store) FindLinkedUser(ctx context.Context, tenantID, providerID uuid.UUID, subject string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT f.user_id FROM federated_identities f JOIN users u ON u.id = f.user_id AND u.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND f.provider_id = $2 AND f.subject = $3 AND u.deleted_at IS NULL`, tenantID, providerID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return userID, err
}

func (s *Store) ListLinks(ctx context.Context, tenantID, userID uuid.UUID) ([]web.LinkedAccount, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.name, f.email FROM federated_identities f JOIN identity_providers p ON p.id = f.provider_id
		WHERE f.tenant_id = $1 AND f.user_id = $2 ORDER BY f.linked_at`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (web.LinkedAccount, error) {
		var l web.LinkedAccount
		return l, r.Scan(&l.ProviderName, &l.Email)
	})
}
