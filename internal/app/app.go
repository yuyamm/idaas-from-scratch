// Package app wires the modules into one HTTP server.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yuyamm/idaas-from-scratch/internal/adminapi"
	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/federation"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/keys"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/mail"
	"github.com/yuyamm/idaas-from-scratch/internal/scim"
	"github.com/yuyamm/idaas-from-scratch/internal/web"
)

type Config struct {
	Pool           *pgxpool.Pool
	BaseURL        string
	EncryptionKeys map[string][]byte
	ActiveKeyID    string
	PasswordParams *authn.Argon2Params // nil = authn.DefaultArgon2Params
	Mailer         mail.Sender         // nil = log only
	HTTPClient     *http.Client        // for outbound calls (back-channel logout, webhooks, external IdPs)
	BreachCheck    authn.BreachChecker
}

type App struct {
	cfg      Config
	enc      crypto.Encrypter
	ids      *identity.Store
	authn    *authn.Service
	keys     *keys.Service
	clients  *oidc.ClientStore
	provider *oidc.Provider
	webhooks *audit.WebhookStore
	relay    *audit.Relay
	fed      *federation.Store
	web      *web.Server
	handler  http.Handler
}

func New(cfg Config) (*App, error) {
	if cfg.Pool == nil || cfg.BaseURL == "" {
		return nil, errors.New("app: Pool and BaseURL are required")
	}
	enc, err := crypto.NewAESGCM(cfg.ActiveKeyID, cfg.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	params := authn.DefaultArgon2Params
	if cfg.PasswordParams != nil {
		params = *cfg.PasswordParams
	}
	if cfg.Mailer == nil {
		cfg.Mailer = mail.Log{}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	opts := []authn.Option{authn.WithEncrypter(enc)}
	if cfg.BreachCheck != nil {
		opts = append(opts, authn.WithBreachChecker(cfg.BreachCheck))
	}
	a := &App{cfg: cfg, enc: enc}
	a.ids = identity.NewStore(cfg.Pool)
	a.authn = authn.NewService(cfg.Pool, authn.NewPasswordHasher(params), opts...)
	a.keys = keys.NewService(cfg.Pool, enc)
	a.clients = oidc.NewClientStore(cfg.Pool)
	a.provider = oidc.NewProvider(cfg.Pool, cfg.BaseURL, a.ids, a.clients, a.keys, a.authn, oidc.WithHTTPClient(cfg.HTTPClient))
	a.webhooks = audit.NewWebhookStore(cfg.Pool, enc)
	a.relay = audit.NewRelay(cfg.Pool, a.webhooks)
	a.fed = federation.NewStore(cfg.Pool, enc)
	a.web = web.NewServer(a.ids, a.authn, a.provider, enc, cfg.Mailer, cfg.BaseURL)

	mux := http.NewServeMux()
	a.web.Routes(mux, federation.NewRP(a.fed, cfg.HTTPClient), federation.NewSAMLIdP(a.fed), web.Passkeys{}, scim.New())
	mux.Handle("/admin/v1/", adminapi.NewServer(a.ids, a.authn, a.provider, a.keys, a.webhooks, a.relay, a.fed).Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	a.handler = web.Middleware(mux)
	return a, nil
}

func (a *App) Handler() http.Handler         { return a.handler }
func (a *App) Identity() *identity.Store     { return a.ids }
func (a *App) Authn() *authn.Service         { return a.authn }
func (a *App) Keys() *keys.Service           { return a.keys }
func (a *App) Clients() *oidc.ClientStore    { return a.clients }
func (a *App) Provider() *oidc.Provider      { return a.provider }
func (a *App) Relay() *audit.Relay           { return a.relay }
func (a *App) Webhooks() *audit.WebhookStore { return a.webhooks }

// RunBackground runs the outbox relay and signing key retirement until ctx
// is done.
func (a *App) RunBackground(ctx context.Context) {
	go a.retireKeys(ctx, 10*time.Minute)
	a.relay.Run(ctx, 2*time.Second)
}

// retireKeys moves retiring keys to retired once every token they signed has
// expired.
func (a *App) retireKeys(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		cursor := ""
		for {
			tenants, next, err := a.ids.ListTenants(ctx, 200, cursor)
			if err != nil {
				slog.Error("key retirement", "err", err)
				break
			}
			for _, tn := range tenants {
				maxLifetime := max(tn.Settings.AccessTokenTTL(), tn.Settings.IDTokenTTL())
				if err := a.keys.RetireExpired(ctx, tn.ID, maxLifetime); err != nil {
					slog.Error("key retirement", "tenant", tn.Slug, "err", err)
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) Federation() *federation.Store { return a.fed }

// Bootstrap ensures the admin tenant exists and registers a new Admin API
// client, returning its client_id and secret.
func (a *App) Bootstrap(ctx context.Context) (string, string, error) {
	t, err := a.ids.GetTenantBySlug(ctx, adminapi.AdminTenantSlug)
	if errors.Is(err, identity.ErrNotFound) {
		t, err = a.ids.CreateTenant(ctx, adminapi.AdminTenantSlug, "Administration")
		if errors.Is(err, identity.ErrConflict) {
			t, err = a.ids.GetTenantBySlug(ctx, adminapi.AdminTenantSlug)
		}
	}
	if err != nil {
		return "", "", err
	}
	c, secret, err := a.clients.Create(ctx, t.ID, oidc.NewClient{
		Name: "admin-api", Type: oidc.Confidential, AuthMethod: oidc.ClientSecretBasic,
		GrantTypes: []string{"client_credentials"}, AllowedScopes: []string{"admin:read", "admin:write", "admin:audit:read"},
	})
	if err != nil {
		return "", "", err
	}
	return c.ClientID, secret, nil
}
