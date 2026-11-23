package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

const (
	passkeyCookie  = "idaas_webauthn"
	passkeyPurpose = "webauthn"
)

// Passkeys adds WebAuthn registration and login.
type Passkeys struct{}

func (Passkeys) Routes(mux *http.ServeMux, s *Server) {
	s.Tenant(mux, "GET /passkey/register", s.passkeyRegisterPage)
	s.Tenant(mux, "POST /passkey/register/begin", s.passkeyRegisterBegin)
	s.Tenant(mux, "POST /passkey/register/finish", s.passkeyRegisterFinish)
	s.Tenant(mux, "GET /passkey/login", s.passkeyLoginPage)
	s.Tenant(mux, "POST /passkey/login/begin", s.passkeyLoginBegin)
	s.Tenant(mux, "POST /passkey/login/finish", s.passkeyLoginFinish)
}

func (s *Server) checkCSRFHeader(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	return err == nil && c.Value != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.Header.Get("X-CSRF-Token"))) == 1
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) saveCeremony(w http.ResponseWriter, t identity.Tenant, sd *webauthn.SessionData) error {
	sealed, err := s.seal(passkeyPurpose, t, sd)
	if err != nil {
		return err
	}
	s.setCookie(w, t, passkeyCookie, sealed, 5*time.Minute)
	return nil
}

func (s *Server) loadCeremony(w http.ResponseWriter, r *http.Request, t identity.Tenant) (webauthn.SessionData, bool) {
	var sd webauthn.SessionData
	c, err := r.Cookie(passkeyCookie)
	if err != nil || s.open(passkeyPurpose, t, c.Value, &sd) != nil {
		return sd, false
	}
	s.setCookie(w, t, passkeyCookie, "", 0) // one ceremony per challenge
	return sd, true
}

// ---------------------------------------------------------------- registration

func (s *Server) passkeyRegisterPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if _, ok := s.CurrentSession(r, t); !ok {
		http.Redirect(w, r, s.tenantBase(t)+"/login?return_to="+s.tenantBase(t)+"/passkey/register", http.StatusFound)
		return
	}
	s.render(w, r, t, http.StatusOK, "passkey", view{Title: "パスキーの登録", Data: map[string]bool{"Register": true}})
}

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	sess, ok := s.CurrentSession(r, t)
	if !ok || !s.checkCSRFHeader(r) {
		jsonError(w, http.StatusUnauthorized, "login required")
		return
	}
	wa, err := authn.WebAuthn(s.base, t)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	user, err := s.authn.PasskeyUser(r.Context(), t.ID, sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, len(user.Credentials))
	for i, c := range user.Credentials {
		exclude[i] = c.Descriptor()
	}
	opts, sd, err := wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.saveCeremony(w, t, sd); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	sess, ok := s.CurrentSession(r, t)
	if !ok || !s.checkCSRFHeader(r) {
		jsonError(w, http.StatusUnauthorized, "login required")
		return
	}
	sd, ok := s.loadCeremony(w, r, t)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no registration in progress")
		return
	}
	wa, err := authn.WebAuthn(s.base, t)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	user, err := s.authn.PasskeyUser(r.Context(), t.ID, sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cred, err := wa.FinishRegistration(user, sd, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "passkey registration failed")
		return
	}
	if err := s.authn.SavePasskey(r.Context(), t.ID, sess.UserID, cred, "passkey"); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.tenantBase(t) + "/account"})
}

// ---------------------------------------------------------------- login

func (s *Server) passkeyLoginPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	s.render(w, r, t, http.StatusOK, "passkey", view{Title: "パスキーでログイン", ReturnTo: r.URL.Query().Get("return_to"), Data: map[string]bool{"Register": false}})
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRFHeader(r) {
		jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if !s.allowIP(r, t) {
		tooMany(w)
		return
	}
	wa, err := authn.WebAuthn(s.base, t)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	opts, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.saveCeremony(w, t, sd); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRFHeader(r) {
		jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	sd, ok := s.loadCeremony(w, r, t)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no login in progress")
		return
	}
	wa, err := authn.WebAuthn(s.base, t)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var userID uuid.UUID
	cred, err := wa.FinishDiscoverableLogin(func(rawID, handle []byte) (webauthn.User, error) {
		u, err := s.authn.PasskeyUserByHandle(r.Context(), t.ID, handle)
		if err != nil {
			return nil, err
		}
		if u.User.Status != identity.StatusActive {
			return nil, errors.New("user is not active")
		}
		userID = u.User.ID
		return u, nil
	}, sd, r)
	if err != nil || cred.Authenticator.CloneWarning {
		jsonError(w, http.StatusUnauthorized, "passkey authentication failed")
		return
	}
	if err := s.authn.UpdatePasskeyAfterLogin(r.Context(), t.ID, cred); err != nil {
		s.internalError(w, r, err)
		return
	}
	redirect, err := s.startSession(w, r, t, userID, authn.ACRMFA, []string{"hwk"}, r.URL.Query().Get("return_to"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
}
