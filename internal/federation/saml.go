package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/web"
)

const (
	samlCookie  = "idaas_saml"
	samlPurpose = "saml-request"
)

// SAMLIdP serves SP-initiated SSO (HTTP-Redirect and HTTP-POST bindings).
// Parsing, signing and XML signature handling are delegated to crewjam/saml.
type SAMLIdP struct {
	store *Store
}

func NewSAMLIdP(store *Store) *SAMLIdP { return &SAMLIdP{store: store} }

func (x *SAMLIdP) Routes(mux *http.ServeMux, s *web.Server) {
	s.Tenant(mux, "GET /saml/metadata", func(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
		idp, err := x.idp(r.Context(), s, t)
		if err != nil {
			s.InternalError(w, r, err)
			return
		}
		idp.ServeMetadata(w, r)
	})
	sso := func(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
		idp, err := x.idp(r.Context(), s, t)
		if err != nil {
			s.InternalError(w, r, err)
			return
		}
		idp.ServeSSO(w, r)
	}
	s.Tenant(mux, "GET /saml/sso", sso)
	s.Tenant(mux, "POST /saml/sso", sso)
	s.Tenant(mux, "GET /saml/sso/resume", x.resume(s))
}

func samlAAD(t identity.Tenant) []byte { return []byte("saml-idp:" + t.ID.String()) }

// keyPair loads (or creates) the tenant's SAML signing key and certificate.
func (x *SAMLIdP) keyPair(ctx context.Context, s *web.Server, t identity.Tenant) (*rsa.PrivateKey, *x509.Certificate, error) {
	var der, ct []byte
	var keyID string
	err := x.store.pool.QueryRow(ctx, `SELECT certificate_der, private_key_encrypted, encryption_key_id FROM saml_idp_keys WHERE tenant_id = $1`, t.ID).Scan(&der, &ct, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: s.BaseURL() + s.TenantBase(t)},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, nil, err
		}
		if ct, keyID, err = s.Encrypter().Encrypt(x509.MarshalPKCS1PrivateKey(key), samlAAD(t)); err != nil {
			return nil, nil, err
		}
		if _, err := x.store.pool.Exec(ctx, `INSERT INTO saml_idp_keys (tenant_id, certificate_der, private_key_encrypted, encryption_key_id)
			VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id) DO NOTHING`, t.ID, der, ct, keyID); err != nil {
			return nil, nil, err
		}
		return x.keyPair(ctx, s, t) // re-read in case another request won the race
	}
	if err != nil {
		return nil, nil, err
	}
	pkcs1, err := s.Encrypter().Decrypt(ct, keyID, samlAAD(t))
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(pkcs1)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}

func (x *SAMLIdP) idp(ctx context.Context, s *web.Server, t identity.Tenant) (*saml.IdentityProvider, error) {
	key, cert, err := x.keyPair(ctx, s, t)
	if err != nil {
		return nil, err
	}
	base := s.BaseURL() + s.TenantBase(t)
	metadataURL, _ := url.Parse(base + "/saml/metadata")
	ssoURL, _ := url.Parse(base + "/saml/sso")
	return &saml.IdentityProvider{
		Key: key, Certificate: cert, MetadataURL: *metadataURL, SSOURL: *ssoURL, Logger: logger.DefaultLogger,
		ServiceProviderProvider: spProvider{store: x.store, tenant: t},
		SessionProvider:         sessionProvider{s: s, t: t, store: x.store},
	}, nil
}

type spProvider struct {
	store  *Store
	tenant identity.Tenant
}

func (p spProvider) GetServiceProvider(r *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	sp, err := p.store.GetSAMLSPByEntityID(r.Context(), p.tenant.ID, entityID)
	if err != nil {
		return nil, os.ErrNotExist
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(sp.MetadataXML), &ed); err != nil {
		return nil, os.ErrNotExist
	}
	return &ed, nil
}

type sessionProvider struct {
	s     *web.Server
	t     identity.Tenant
	store *Store
}

// pendingSAML keeps an HTTP-POST AuthnRequest across the login so it can be
// re-posted afterwards.
type pendingSAML struct {
	SAMLRequest string `json:"req"`
	RelayState  string `json:"rs"`
}

func (p sessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	sess, ok := p.s.CurrentSession(r, p.t)
	forceAuthn := req.Request.ForceAuthn != nil && *req.Request.ForceAuthn
	if ok && forceAuthn && time.Since(sess.AuthTime) > time.Minute {
		ok = false
	}
	if !ok {
		returnTo := r.URL.RequestURI()
		if r.Method == http.MethodPost {
			sealed, err := p.s.Seal(samlPurpose, p.t, pendingSAML{SAMLRequest: r.PostForm.Get("SAMLRequest"), RelayState: r.PostForm.Get("RelayState")})
			if err != nil {
				p.s.InternalError(w, r, err)
				return nil
			}
			p.s.SetCookie(w, p.t, samlCookie, sealed, 10*time.Minute)
			returnTo = p.s.TenantBase(p.t) + "/saml/sso/resume"
		}
		http.Redirect(w, r, p.s.TenantBase(p.t)+"/login?"+url.Values{"return_to": {returnTo}}.Encode(), http.StatusFound)
		return nil
	}
	u, err := p.s.Identity().GetUser(r.Context(), p.t.ID, sess.UserID)
	if err != nil || u.Status != identity.StatusActive {
		p.s.Message(w, r, p.t, http.StatusForbidden, "ログインできません", "アカウントが無効です。")
		return nil
	}
	roles, _ := p.s.Identity().EffectiveRoles(r.Context(), p.t.ID, u.ID)
	audit.Record(r.Context(), p.store.pool, audit.Event{TenantID: p.t.ID, Type: "user.saml_sso", TargetType: "user", TargetID: u.ID.String(),
		Data: map[string]any{"service_provider": req.ServiceProviderMetadata.EntityID}, Actor: &audit.Actor{Type: audit.ActorUser, ID: u.ID.String()}})
	return &saml.Session{
		ID: sess.ID.String(), CreateTime: sess.AuthTime, ExpireTime: sess.ExpiresAt, Index: sess.ID.String(),
		NameID: u.ID.String(), NameIDFormat: string(saml.PersistentNameIDFormat),
		UserName: u.LoginID, UserEmail: u.Email, UserCommonName: u.Name(), UserGivenName: u.GivenName, UserSurname: u.FamilyName,
		Groups: roles,
	}
}

var resumeTmpl = template.Must(template.New("resume").Parse(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>SAML</title></head>
<body onload="document.forms[0].submit()"><form method="post" action="{{.Action}}">
<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}"><input type="hidden" name="RelayState" value="{{.RelayState}}">
<noscript><button type="submit">続ける</button></noscript></form></body></html>`))

// resume re-posts an HTTP-POST AuthnRequest after the user logged in.
func (x *SAMLIdP) resume(s *web.Server) func(http.ResponseWriter, *http.Request, identity.Tenant) {
	return func(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
		c, err := r.Cookie(samlCookie)
		var p pendingSAML
		if err != nil || s.Open(samlPurpose, t, c.Value, &p) != nil {
			s.Message(w, r, t, http.StatusBadRequest, "リクエストが不正です", "SAML リクエストが見つかりません。")
			return
		}
		s.SetCookie(w, t, samlCookie, "", 0)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; form-action 'self'")
		resumeTmpl.Execute(w, map[string]string{"Action": s.TenantBase(t) + "/saml/sso", "SAMLRequest": p.SAMLRequest, "RelayState": p.RelayState})
	}
}
