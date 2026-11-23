package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

const msgInvalidCredentials = "ログイン ID またはパスワードが正しくありません。"

// pendingLogin is the state between the password step and the MFA step,
// kept in an encrypted, short-lived cookie.
type pendingLogin struct {
	UserID   uuid.UUID `json:"uid"`
	AMR      []string  `json:"amr"`
	ReturnTo string    `json:"rt"`
	Exp      int64     `json:"exp"`
	Codes    []string  `json:"codes,omitempty"` // recovery codes to show once after enrollment
}

const flowPurpose = "login-flow"

func (s *Server) pending(r *http.Request, t identity.Tenant) (pendingLogin, bool) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return pendingLogin{}, false
	}
	var p pendingLogin
	if s.open(flowPurpose, t, c.Value, &p) != nil || time.Now().Unix() > p.Exp {
		return pendingLogin{}, false
	}
	return p, true
}

func (s *Server) setPending(w http.ResponseWriter, t identity.Tenant, p pendingLogin) error {
	p.Exp = time.Now().Add(10 * time.Minute).Unix()
	v, err := s.seal(flowPurpose, t, p)
	if err != nil {
		return err
	}
	s.setCookie(w, t, flowCookie, v, 10*time.Minute)
	return nil
}

// ---------------------------------------------------------------- login

type loginData struct {
	LoginID   string
	Providers []LoginProvider
}

func (s *Server) loginView(r *http.Request, t identity.Tenant, loginID, returnTo, errMsg string) view {
	d := loginData{LoginID: loginID}
	if s.Providers != nil {
		d.Providers = s.Providers(r.Context(), t)
	}
	return view{Title: "ログイン", ReturnTo: returnTo, Error: errMsg, Data: d}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	s.render(w, r, t, http.StatusOK, "login", s.loginView(r, t, r.URL.Query().Get("login_hint"), r.URL.Query().Get("return_to"), ""))
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	loginID, returnTo := strings.TrimSpace(r.PostFormValue("login_id")), r.PostFormValue("return_to")
	if !s.allowIP(r, t) || !s.allowAccount(t, loginID) {
		tooMany(w)
		return
	}
	u, err := s.authn.VerifyPassword(r.Context(), t, loginID, r.PostFormValue("password"))
	if err != nil && !errors.Is(err, authn.ErrInvalidCredentials) {
		// Allow login with the email address as well.
		s.internalError(w, r, err)
		return
	}
	if errors.Is(err, authn.ErrInvalidCredentials) && strings.Contains(loginID, "@") {
		if byEmail, ferr := s.ids.FindUserByEmail(r.Context(), t.ID, loginID); ferr == nil {
			u, err = s.authn.VerifyPassword(r.Context(), t, byEmail.LoginID, r.PostFormValue("password"))
		}
	}
	if err != nil {
		s.render(w, r, t, http.StatusUnauthorized, "login", s.loginView(r, t, loginID, returnTo, msgInvalidCredentials))
		return
	}
	s.afterPrimaryAuth(w, r, t, u.ID, []string{"pwd"}, returnTo)
}

// AfterPrimaryAuth continues a login after the first factor (password or an
// external IdP): it asks for MFA when required, then starts the session.
func (s *Server) AfterPrimaryAuth(w http.ResponseWriter, r *http.Request, t identity.Tenant, userID uuid.UUID, amr []string, returnTo string) {
	s.afterPrimaryAuth(w, r, t, userID, amr, returnTo)
}

func (s *Server) afterPrimaryAuth(w http.ResponseWriter, r *http.Request, t identity.Tenant, userID uuid.UUID, amr []string, returnTo string) {
	hasMFA, err := s.authn.HasMFA(r.Context(), t.ID, userID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !hasMFA && !t.Settings.MFARequired && !wantsMFA(returnTo) {
		s.CompleteLogin(w, r, t, userID, authn.ACRPassword, amr, returnTo)
		return
	}
	if err := s.setPending(w, t, pendingLogin{UserID: userID, AMR: amr, ReturnTo: returnTo}); err != nil {
		s.internalError(w, r, err)
		return
	}
	next := "/mfa"
	if !hasMFA {
		next = "/mfa/setup"
	}
	http.Redirect(w, r, s.tenantBase(t)+next, http.StatusFound)
}

func wantsMFA(returnTo string) bool {
	u, err := url.Parse(returnTo)
	if err != nil {
		return false
	}
	return slices.Contains(strings.Fields(u.Query().Get("acr_values")), authn.ACRMFA)
}

// ---------------------------------------------------------------- MFA

func (s *Server) mfaPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if _, ok := s.pending(r, t); !ok {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	s.render(w, r, t, http.StatusOK, "mfa", view{Title: "2 段階認証"})
}

func (s *Server) mfaSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	p, ok := s.pending(r, t)
	if !ok || !s.checkCSRF(r) {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	if !s.allowIP(r, t) || !s.allowAccount(t, p.UserID.String()) {
		tooMany(w)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	ctx := r.Context()
	method := "otp"
	err := s.authn.VerifyTOTP(ctx, t, p.UserID, code)
	if errors.Is(err, authn.ErrInvalidOTP) && strings.Contains(code, "-") {
		method = "mfa"
		err = s.authn.UseRecoveryCode(ctx, t, p.UserID, code)
	}
	if errors.Is(err, authn.ErrInvalidOTP) {
		s.render(w, r, t, http.StatusUnauthorized, "mfa", view{Title: "2 段階認証", Error: "コードが正しくありません。"})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.CompleteLogin(w, r, t, p.UserID, authn.ACRMFA, append(p.AMR, method), p.ReturnTo)
}

func (s *Server) mfaSetupPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	userID, ok := s.mfaSetupUser(r, t)
	if !ok {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	enr, err := s.authn.EnrollTOTP(r.Context(), t, userID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, t, http.StatusOK, "mfa_setup", view{Title: "認証アプリの登録", Data: enr})
}

// mfaSetupUser is the user enrolling TOTP: either mid-login (pending) or a
// signed-in user from the account page.
func (s *Server) mfaSetupUser(r *http.Request, t identity.Tenant) (uuid.UUID, bool) {
	if p, ok := s.pending(r, t); ok {
		return p.UserID, true
	}
	if sess, ok := s.CurrentSession(r, t); ok {
		return sess.UserID, true
	}
	return uuid.Nil, false
}

func (s *Server) mfaSetupSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	userID, ok := s.mfaSetupUser(r, t)
	if !ok || !s.checkCSRF(r) {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	codes, err := s.authn.ConfirmTOTP(r.Context(), t, userID, r.PostFormValue("code"))
	if errors.Is(err, authn.ErrInvalidOTP) {
		enr, eerr := s.authn.EnrollTOTP(r.Context(), t, userID)
		if eerr != nil {
			s.internalError(w, r, eerr)
			return
		}
		s.render(w, r, t, http.StatusUnauthorized, "mfa_setup", view{Title: "認証アプリの登録", Error: "コードが正しくありません。もう一度登録してください。", Data: enr})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if p, ok := s.pending(r, t); ok {
		p.AMR = append(p.AMR, "otp")
		if err := s.setPending(w, t, p); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	s.render(w, r, t, http.StatusOK, "recovery_codes", view{Title: "リカバリーコード", Data: map[string]any{"Codes": codes}})
}

// mfaContinue finishes a login that just enrolled TOTP.
func (s *Server) mfaContinue(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	p, ok := s.pending(r, t)
	if !ok || !s.checkCSRF(r) {
		http.Redirect(w, r, s.tenantBase(t)+"/account", http.StatusFound)
		return
	}
	if has, _ := s.authn.HasMFA(r.Context(), t.ID, p.UserID); !has {
		http.Redirect(w, r, s.tenantBase(t)+"/mfa/setup", http.StatusFound)
		return
	}
	s.CompleteLogin(w, r, t, p.UserID, authn.ACRMFA, p.AMR, p.ReturnTo)
}

// ---------------------------------------------------------------- password reset & email verification

func (s *Server) forgotPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	s.render(w, r, t, http.StatusOK, "forgot", view{Title: "パスワードの再設定"})
}

func (s *Server) forgotSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	loginID := strings.TrimSpace(r.PostFormValue("login_id"))
	if !s.allowIP(r, t) || !s.allowAccount(t, "reset|"+loginID) {
		tooMany(w)
		return
	}
	token, u, ok, err := s.authn.RequestPasswordReset(r.Context(), t, loginID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if ok {
		link := s.base + s.tenantBase(t) + "/reset?token=" + url.QueryEscape(token)
		// Send asynchronously so the response time does not depend on whether
		// the account exists.
		go s.mailer.Send(contextWithoutCancel(r), u.Email, "パスワードの再設定",
			"次のリンクからパスワードを再設定してください（30 分間有効）。\n\n"+link+"\n\n心当たりがない場合はこのメールを無視してください。")
	}
	s.message(w, r, t, http.StatusOK, "メールを確認してください", "入力されたアカウントが存在する場合、パスワード再設定用のリンクをメールで送信しました。")
}

func (s *Server) resetPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	s.render(w, r, t, http.StatusOK, "reset", view{Title: "新しいパスワード", Data: map[string]string{"Token": r.URL.Query().Get("token")}})
}

func (s *Server) resetSubmit(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	token := r.PostFormValue("token")
	err := s.authn.ResetPassword(r.Context(), t, token, r.PostFormValue("password"))
	switch {
	case errors.Is(err, authn.ErrWeakPassword), errors.Is(err, authn.ErrBreachedPassword):
		msg := "パスワードが短すぎます。"
		if errors.Is(err, authn.ErrBreachedPassword) {
			msg = "このパスワードは過去の漏洩で見つかっています。別のパスワードを使ってください。"
		}
		s.render(w, r, t, http.StatusBadRequest, "reset", view{Title: "新しいパスワード", Error: msg, Data: map[string]string{"Token": token}})
	case errors.Is(err, authn.ErrInvalidToken):
		s.message(w, r, t, http.StatusBadRequest, "リンクが無効です", "リンクの有効期限が切れているか、すでに使用されています。")
	case err != nil:
		s.internalError(w, r, err)
	default:
		s.render(w, r, t, http.StatusOK, "message", view{Title: "パスワードを変更しました", Data: map[string]string{
			"Message": "新しいパスワードでログインしてください。", "Link": s.tenantBase(t) + "/account", "LinkText": "ログイン"}})
	}
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if err := s.authn.VerifyEmail(r.Context(), t, r.URL.Query().Get("token")); err != nil {
		s.message(w, r, t, http.StatusBadRequest, "リンクが無効です", "リンクの有効期限が切れているか、すでに使用されています。")
		return
	}
	s.message(w, r, t, http.StatusOK, "メールアドレスを確認しました", "メールアドレスの確認が完了しました。")
}

// ---------------------------------------------------------------- account

type accountData struct {
	User      identity.User
	Factors   []authn.MFAFactor
	Providers []LoginProvider
	Links     []LinkedAccount
}

// LinkedAccount is an external account linked to the user.
type LinkedAccount struct {
	ProviderName string
	Email        string
}

// Linked lists linked external accounts (set by the federation module).
var Linked func(r *http.Request, t identity.Tenant, userID uuid.UUID) []LinkedAccount

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	sess, ok := s.CurrentSession(r, t)
	if !ok {
		http.Redirect(w, r, s.tenantBase(t)+"/login?return_to="+url.QueryEscape(s.tenantBase(t)+"/account"), http.StatusFound)
		return
	}
	u, err := s.ids.GetUser(r.Context(), t.ID, sess.UserID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	factors, err := s.authn.ListMFAFactors(r.Context(), t.ID, u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	d := accountData{User: u, Factors: factors}
	if s.Providers != nil {
		d.Providers = s.Providers(r.Context(), t)
	}
	if Linked != nil {
		d.Links = Linked(r, t, u.ID)
	}
	info := ""
	if r.URL.Query().Get("linked") == "1" {
		info = "外部アカウントを連携しました。"
	}
	s.render(w, r, t, http.StatusOK, "account", view{Title: "アカウント", Info: info, Data: d})
}

func (s *Server) accountVerifyEmail(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	sess, ok := s.CurrentSession(r, t)
	if !ok || !s.checkCSRF(r) {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	if err := s.SendVerificationMail(r, t, sess.UserID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.message(w, r, t, http.StatusOK, "確認メールを送信しました", "メールに記載されたリンクを開いてください。")
}

// SendVerificationMail issues an email verification token and mails it.
func (s *Server) SendVerificationMail(r *http.Request, t identity.Tenant, userID uuid.UUID) error {
	u, err := s.ids.GetUser(r.Context(), t.ID, userID)
	if err != nil {
		return err
	}
	token, err := s.authn.IssueEmailVerification(r.Context(), t, userID)
	if err != nil {
		return err
	}
	link := s.base + s.tenantBase(t) + "/verify-email?token=" + url.QueryEscape(token)
	return s.mailer.Send(r.Context(), u.Email, "メールアドレスの確認", "次のリンクを開いてメールアドレスを確認してください（24 時間有効）。\n\n"+link)
}

func (s *Server) accountTOTP(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	if _, ok := s.CurrentSession(r, t); !ok || !s.checkCSRF(r) {
		http.Redirect(w, r, s.tenantBase(t)+"/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, s.tenantBase(t)+"/mfa/setup", http.StatusSeeOther)
}
