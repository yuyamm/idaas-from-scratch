package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/federation"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/keys"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

// AdminTenantSlug is the tenant whose clients may call the Admin API.
const AdminTenantSlug = "admin"

// Server implements StrictServerInterface.
type Server struct {
	ids      *identity.Store
	authn    *authn.Service
	clients  *oidc.ClientStore
	provider *oidc.Provider
	keys     *keys.Service
	webhooks *audit.WebhookStore
	relay    *audit.Relay
	fed      *federation.Store
}

func NewServer(ids *identity.Store, an *authn.Service, p *oidc.Provider, ks *keys.Service, ws *audit.WebhookStore, relay *audit.Relay, fed *federation.Store) *Server {
	return &Server{ids: ids, authn: an, clients: p.Clients(), provider: p, keys: ks, webhooks: ws, relay: relay, fed: fed}
}

// Handler serves the Admin API under /admin/v1.
func (s *Server) Handler() http.Handler {
	strict := NewStrictHandlerWithOptions(s, nil, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeProblem(w, http.StatusBadRequest, err.Error())
		},
		ResponseErrorHandlerFunc: s.writeError,
	})
	mux := http.NewServeMux()
	h := HandlerWithOptions(strict, StdHTTPServerOptions{BaseURL: "/admin/v1", BaseRouter: mux})
	return s.authenticate(h)
}

// ---------------------------------------------------------------- auth

func requiredScope(r *http.Request) string {
	switch {
	case strings.Contains(r.URL.Path, "/audit-logs"):
		return "admin:audit:read"
	case r.Method == http.MethodGet:
		return "admin:read"
	default:
		return "admin:write"
	}
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			token = h[7:]
		}
		adminTenant, err := s.ids.GetTenantBySlug(r.Context(), AdminTenantSlug)
		if err != nil || token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="idaas-admin"`)
			writeProblem(w, http.StatusUnauthorized, "a bearer token is required")
			return
		}
		info, err := s.provider.AuthenticateBearer(r.Context(), adminTenant, token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeProblem(w, http.StatusUnauthorized, "invalid token")
			return
		}
		scope := requiredScope(r)
		if !contains(info.Scopes, scope) {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
			writeProblem(w, http.StatusForbidden, "scope "+scope+" is required")
			return
		}
		ctx := audit.WithActor(r.Context(), audit.Actor{Type: audit.ActorAdmin, ID: info.ClientID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- errors

type apiError struct {
	status int
	detail string
}

func (e apiError) Error() string { return e.detail }

func badRequest(msg string) error { return apiError{http.StatusBadRequest, msg} }

var errPrecondition = apiError{http.StatusPreconditionFailed, "the resource was modified; fetch it again and retry with the new ETag"}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	title := http.StatusText(status)
	json.NewEncoder(w).Encode(Problem{Type: "https://idaas.example.com/problems/" + strings.ReplaceAll(strings.ToLower(title), " ", "-"),
		Title: title, Status: status, Detail: &detail})
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var ae apiError
	switch {
	case errors.As(err, &ae):
		writeProblem(w, ae.status, ae.detail)
	case errors.Is(err, identity.ErrNotFound), errors.Is(err, oidc.ErrClientNotFound), errors.Is(err, federation.ErrNotFound),
		errors.Is(err, audit.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		writeProblem(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, identity.ErrConflict), errors.Is(err, oidc.ErrClientConflict), errors.Is(err, federation.ErrConflict):
		writeProblem(w, http.StatusConflict, "the resource conflicts with an existing one")
	case errors.Is(err, identity.ErrVersionMismatch), errors.Is(err, oidc.ErrVersion):
		writeProblem(w, http.StatusPreconditionFailed, errPrecondition.detail)
	case errors.Is(err, identity.ErrInvalidCursor), errors.Is(err, federation.ErrInvalid):
		writeProblem(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, authn.ErrWeakPassword), errors.Is(err, authn.ErrBreachedPassword):
		writeProblem(w, http.StatusUnprocessableEntity, err.Error())
	default:
		slog.ErrorContext(r.Context(), "admin api", "path", r.URL.Path, "err", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
	}
}

// ---------------------------------------------------------------- helpers

func etag(version int64) string { return `"v` + strconv.FormatInt(version, 10) + `"` }

func parseIfMatch(h string) (int64, error) {
	h = strings.TrimPrefix(strings.TrimSpace(h), "W/")
	v, err := strconv.ParseInt(strings.TrimPrefix(strings.Trim(h, `"`), "v"), 10, 64)
	if err != nil || v <= 0 {
		return 0, errPrecondition
	}
	return v, nil
}

func meta(created, updated time.Time, version int64) *Meta {
	return &Meta{Created: created, LastModified: updated, Version: etag(version)}
}

func pageSize(p *PageSize) int {
	if p == nil || *p <= 0 {
		return 50
	}
	return min(int(*p), 200)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func next(token string) *string { return strPtr(token) }

func (s *Server) tenant(ctx context.Context, id TenantId) (identity.Tenant, error) {
	return s.ids.GetTenant(ctx, id)
}

func (s *Server) issuer(t identity.Tenant) string { return s.provider.Issuer(t) }

// ---------------------------------------------------------------- tenants

func (s *Server) tenantDTO(t identity.Tenant) Tenant {
	st := t.Settings
	ip := func(v int) *int {
		if v == 0 {
			return nil
		}
		return &v
	}
	return Tenant{Id: &t.ID, Slug: t.Slug, Name: t.Name, Issuer: strPtr(s.issuer(t)), Meta: meta(t.CreatedAt, t.UpdatedAt, t.Version),
		Settings: &TenantSettings{
			PasswordMinLength: ip(st.PasswordMinLength), PasswordBreachCheck: &st.PasswordBreachCheck, MfaRequired: &st.MFARequired,
			LockoutThreshold: ip(st.LockoutThreshold), LockoutDurationSeconds: ip(st.LockoutDurationSeconds),
			SessionIdleTimeoutSeconds: ip(st.SessionIdleTimeoutSeconds), SessionAbsoluteTimeoutSeconds: ip(st.SessionAbsoluteTimeoutSeconds),
			AccessTokenTtlSeconds: ip(st.AccessTokenTTLSeconds), IdTokenTtlSeconds: ip(st.IDTokenTTLSeconds), RefreshTokenTtlSeconds: ip(st.RefreshTokenTTLSeconds),
		}}
}

func applySettings(st *identity.Settings, in *TenantSettings) {
	if in == nil {
		return
	}
	set := func(dst *int, v *int) {
		if v != nil {
			*dst = *v
		}
	}
	set(&st.PasswordMinLength, in.PasswordMinLength)
	set(&st.LockoutThreshold, in.LockoutThreshold)
	set(&st.LockoutDurationSeconds, in.LockoutDurationSeconds)
	set(&st.SessionIdleTimeoutSeconds, in.SessionIdleTimeoutSeconds)
	set(&st.SessionAbsoluteTimeoutSeconds, in.SessionAbsoluteTimeoutSeconds)
	set(&st.AccessTokenTTLSeconds, in.AccessTokenTtlSeconds)
	set(&st.IDTokenTTLSeconds, in.IdTokenTtlSeconds)
	set(&st.RefreshTokenTTLSeconds, in.RefreshTokenTtlSeconds)
	if in.PasswordBreachCheck != nil {
		st.PasswordBreachCheck = *in.PasswordBreachCheck
	}
	if in.MfaRequired != nil {
		st.MFARequired = *in.MfaRequired
	}
}

func (s *Server) ListTenants(ctx context.Context, req ListTenantsRequestObject) (ListTenantsResponseObject, error) {
	ts, nextTok, err := s.ids.ListTenants(ctx, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListTenants200JSONResponse{Items: []Tenant{}, NextPageToken: next(nextTok)}
	for _, t := range ts {
		out.Items = append(out.Items, s.tenantDTO(t))
	}
	return out, nil
}

func (s *Server) CreateTenant(ctx context.Context, req CreateTenantRequestObject) (CreateTenantResponseObject, error) {
	if req.Body == nil || req.Body.Slug == "" || req.Body.Name == "" {
		return nil, badRequest("slug and name are required")
	}
	var st identity.Settings
	applySettings(&st, req.Body.Settings)
	t, err := s.ids.CreateTenantWithSettings(ctx, req.Body.Slug, req.Body.Name, st)
	if err != nil {
		return nil, err
	}
	return CreateTenant201JSONResponse{TenantResponseJSONResponse{Body: s.tenantDTO(t), Headers: TenantResponseResponseHeaders{ETag: ptr(etag(t.Version))}}}, nil
}

func ptr[T any](v T) *T { return &v }

func (s *Server) GetTenant(ctx context.Context, req GetTenantRequestObject) (GetTenantResponseObject, error) {
	t, err := s.tenant(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	return GetTenant200JSONResponse{TenantResponseJSONResponse{Body: s.tenantDTO(t), Headers: TenantResponseResponseHeaders{ETag: ptr(etag(t.Version))}}}, nil
}

func (s *Server) UpdateTenant(ctx context.Context, req UpdateTenantRequestObject) (UpdateTenantResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("body is required")
	}
	t, err := s.tenant(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	name := t.Name
	if req.Body.Name != nil {
		name = *req.Body.Name
	}
	st := t.Settings
	applySettings(&st, req.Body.Settings)
	t, err = s.ids.UpdateTenant(ctx, t.ID, version, name, st)
	if err != nil {
		return nil, err
	}
	return UpdateTenant200JSONResponse{TenantResponseJSONResponse{Body: s.tenantDTO(t), Headers: TenantResponseResponseHeaders{ETag: ptr(etag(t.Version))}}}, nil
}

// ---------------------------------------------------------------- users

func (s *Server) userDTO(ctx context.Context, u identity.User) (User, error) {
	roles, err := s.ids.EffectiveRoles(ctx, u.TenantID, u.ID)
	if err != nil {
		return User{}, err
	}
	return User{Id: &u.ID, UserName: u.LoginID, Email: openapi_types.Email(u.Email), EmailVerified: u.EmailVerified,
		Name: &UserName{GivenName: &u.GivenName, FamilyName: &u.FamilyName}, Status: UserStatus(u.Status), Roles: &roles,
		Meta: meta(u.CreatedAt, u.UpdatedAt, u.Version)}, nil
}

func (s *Server) userResponse(ctx context.Context, u identity.User) (UserResponseJSONResponse, error) {
	dto, err := s.userDTO(ctx, u)
	return UserResponseJSONResponse{Body: dto, Headers: UserResponseResponseHeaders{ETag: ptr(etag(u.Version))}}, err
}

func (s *Server) ListUsers(ctx context.Context, req ListUsersRequestObject) (ListUsersResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	f := identity.UserFilter{LoginID: str(req.Params.UserName)}
	if req.Params.Email != nil {
		f.Email = string(*req.Params.Email)
	}
	if req.Params.Status != nil {
		f.Status = identity.Status(*req.Params.Status)
	}
	users, nextTok, err := s.ids.ListUsers(ctx, req.TenantId, f, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListUsers200JSONResponse{Items: []User{}, NextPageToken: next(nextTok)}
	for _, u := range users {
		dto, err := s.userDTO(ctx, u)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, dto)
	}
	return out, nil
}

func (s *Server) CreateUser(ctx context.Context, req CreateUserRequestObject) (CreateUserResponseObject, error) {
	t, err := s.tenant(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil || b.UserName == "" || b.Email == "" {
		return nil, badRequest("user_name and email are required")
	}
	nu := identity.NewUser{LoginID: b.UserName, Email: string(b.Email)}
	if b.EmailVerified != nil {
		nu.EmailVerified = *b.EmailVerified
	}
	if b.Name != nil {
		nu.GivenName, nu.FamilyName = str(b.Name.GivenName), str(b.Name.FamilyName)
	}
	if b.Password != nil && len([]rune(*b.Password)) < t.Settings.PasswordMin() {
		return nil, apiError{http.StatusUnprocessableEntity, fmt.Sprintf("password must be at least %d characters", t.Settings.PasswordMin())}
	}
	u, err := s.ids.CreateUserAudited(ctx, t.ID, nu)
	if errors.Is(err, identity.ErrConflict) {
		return nil, apiError{http.StatusConflict, "user_name or email is already used"}
	}
	if err != nil {
		return nil, err
	}
	if b.Password != nil {
		if err := s.authn.SetPassword(ctx, t, u.ID, *b.Password); err != nil {
			return nil, err
		}
	}
	res, err := s.userResponse(ctx, u)
	return CreateUser201JSONResponse{res}, err
}

func (s *Server) GetUser(ctx context.Context, req GetUserRequestObject) (GetUserResponseObject, error) {
	u, err := s.ids.GetUser(ctx, req.TenantId, req.UserId)
	if err != nil {
		return nil, err
	}
	res, err := s.userResponse(ctx, u)
	return GetUser200JSONResponse{res}, err
}

func (s *Server) UpdateUser(ctx context.Context, req UpdateUserRequestObject) (UpdateUserResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("body is required")
	}
	p := identity.UserPatch{LoginID: req.Body.UserName}
	if req.Body.Email != nil {
		p.Email = ptr(string(*req.Body.Email))
	}
	if req.Body.Name != nil {
		p.GivenName, p.FamilyName = req.Body.Name.GivenName, req.Body.Name.FamilyName
	}
	u, err := s.ids.UpdateUser(ctx, req.TenantId, req.UserId, version, p)
	if err != nil {
		return nil, err
	}
	res, err := s.userResponse(ctx, u)
	return UpdateUser200JSONResponse{res}, err
}

func (s *Server) DeleteUser(ctx context.Context, req DeleteUserRequestObject) (DeleteUserResponseObject, error) {
	err := postgres.InTx(ctx, s.ids.Pool(), func(tx pgx.Tx) error {
		return oidc.RevokeUserTokensTx(ctx, tx, req.TenantId, req.UserId)
	})
	if err != nil {
		return nil, err
	}
	if err := s.ids.SoftDeleteUser(ctx, req.TenantId, req.UserId); err != nil {
		return nil, err
	}
	return DeleteUser204Response{}, nil
}

func (s *Server) PurgeUser(ctx context.Context, req PurgeUserRequestObject) (PurgeUserResponseObject, error) {
	err := s.ids.PurgeUser(ctx, req.TenantId, req.UserId)
	if errors.Is(err, identity.ErrConflict) {
		return nil, apiError{http.StatusConflict, "only soft-deleted users can be purged"}
	}
	if err != nil {
		return nil, err
	}
	return PurgeUser204Response{}, nil
}

func (s *Server) setStatus(ctx context.Context, tenantID, userID uuid.UUID, st identity.Status) (UserResponseJSONResponse, error) {
	err := postgres.InTx(ctx, s.ids.Pool(), func(tx pgx.Tx) error {
		if err := s.ids.SetStatusAudited(ctx, tx, tenantID, userID, st); err != nil {
			return err
		}
		if st != identity.StatusActive {
			if err := authn.RevokeUserSessionsTx(ctx, tx, tenantID, userID, time.Now()); err != nil {
				return err
			}
			return oidc.RevokeUserTokensTx(ctx, tx, tenantID, userID)
		}
		return nil
	})
	if err != nil {
		return UserResponseJSONResponse{}, err
	}
	u, err := s.ids.GetUser(ctx, tenantID, userID)
	if err != nil {
		return UserResponseJSONResponse{}, err
	}
	return s.userResponse(ctx, u)
}

func (s *Server) DisableUser(ctx context.Context, req DisableUserRequestObject) (DisableUserResponseObject, error) {
	res, err := s.setStatus(ctx, req.TenantId, req.UserId, identity.StatusDisabled)
	return DisableUser200JSONResponse{res}, err
}

func (s *Server) EnableUser(ctx context.Context, req EnableUserRequestObject) (EnableUserResponseObject, error) {
	res, err := s.setStatus(ctx, req.TenantId, req.UserId, identity.StatusActive)
	return EnableUser200JSONResponse{res}, err
}

func (s *Server) UnlockUser(ctx context.Context, req UnlockUserRequestObject) (UnlockUserResponseObject, error) {
	u, err := s.ids.GetUser(ctx, req.TenantId, req.UserId)
	if err != nil {
		return nil, err
	}
	if u.Status == identity.StatusLocked {
		if _, err := s.setStatus(ctx, req.TenantId, req.UserId, identity.StatusActive); err != nil {
			return nil, err
		}
		u, _ = s.ids.GetUser(ctx, req.TenantId, req.UserId)
	}
	res, err := s.userResponse(ctx, u)
	return UnlockUser200JSONResponse{res}, err
}

func (s *Server) SetUserPassword(ctx context.Context, req SetUserPasswordRequestObject) (SetUserPasswordResponseObject, error) {
	t, err := s.tenant(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("password is required")
	}
	if req.Body.Password == nil {
		return nil, badRequest("password is required")
	}
	if err := s.authn.SetPassword(ctx, t, req.UserId, *req.Body.Password); err != nil {
		return nil, err
	}
	return SetUserPassword204Response{}, nil
}

func (s *Server) RevokeUserSessions(ctx context.Context, req RevokeUserSessionsRequestObject) (RevokeUserSessionsResponseObject, error) {
	if _, err := s.ids.GetUser(ctx, req.TenantId, req.UserId); err != nil {
		return nil, err
	}
	if err := s.authn.RevokeUserSessions(ctx, req.TenantId, req.UserId); err != nil {
		return nil, err
	}
	return RevokeUserSessions204Response{}, nil
}

func (s *Server) ListUserMfaFactors(ctx context.Context, req ListUserMfaFactorsRequestObject) (ListUserMfaFactorsResponseObject, error) {
	if _, err := s.ids.GetUser(ctx, req.TenantId, req.UserId); err != nil {
		return nil, err
	}
	fs, err := s.authn.ListMFAFactors(ctx, req.TenantId, req.UserId)
	if err != nil {
		return nil, err
	}
	out := ListUserMfaFactors200JSONResponse{Items: []MfaFactor{}}
	for _, f := range fs {
		out.Items = append(out.Items, MfaFactor{Id: f.ID, Type: MfaFactorType(f.Type), Label: strPtr(f.Label), CreatedAt: f.CreatedAt, LastUsedAt: f.LastUsedAt})
	}
	return out, nil
}

func (s *Server) DeleteUserMfaFactor(ctx context.Context, req DeleteUserMfaFactorRequestObject) (DeleteUserMfaFactorResponseObject, error) {
	if err := s.authn.DeleteMFAFactor(ctx, req.TenantId, req.UserId, req.FactorId); err != nil {
		return nil, err
	}
	return DeleteUserMfaFactor204Response{}, nil
}

func (s *Server) AssignUserRole(ctx context.Context, req AssignUserRoleRequestObject) (AssignUserRoleResponseObject, error) {
	if err := s.ids.AssignUserRole(ctx, req.TenantId, req.UserId, req.RoleId); err != nil {
		return nil, err
	}
	return AssignUserRole204Response{}, nil
}

func (s *Server) UnassignUserRole(ctx context.Context, req UnassignUserRoleRequestObject) (UnassignUserRoleResponseObject, error) {
	if err := s.ids.UnassignUserRole(ctx, req.TenantId, req.UserId, req.RoleId); err != nil {
		return nil, err
	}
	return UnassignUserRole204Response{}, nil
}

// ---------------------------------------------------------------- groups

func (s *Server) groupDTO(ctx context.Context, g identity.Group) (Group, error) {
	roles, err := s.ids.GroupRoles(ctx, g.TenantID, g.ID)
	return Group{Id: &g.ID, Name: g.Name, Roles: &roles, Meta: meta(g.CreatedAt, g.UpdatedAt, g.Version)}, err
}

func (s *Server) groupResponse(ctx context.Context, g identity.Group) (GroupResponseJSONResponse, error) {
	dto, err := s.groupDTO(ctx, g)
	return GroupResponseJSONResponse{Body: dto, Headers: GroupResponseResponseHeaders{ETag: ptr(etag(g.Version))}}, err
}

func (s *Server) ListGroups(ctx context.Context, req ListGroupsRequestObject) (ListGroupsResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	gs, nextTok, err := s.ids.ListGroups(ctx, req.TenantId, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListGroups200JSONResponse{Items: []Group{}, NextPageToken: next(nextTok)}
	for _, g := range gs {
		dto, err := s.groupDTO(ctx, g)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, dto)
	}
	return out, nil
}

func (s *Server) CreateGroup(ctx context.Context, req CreateGroupRequestObject) (CreateGroupResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" {
		return nil, badRequest("name is required")
	}
	g, err := s.ids.CreateGroup(ctx, req.TenantId, req.Body.Name)
	if err != nil {
		return nil, err
	}
	res, err := s.groupResponse(ctx, g)
	return CreateGroup201JSONResponse{res}, err
}

func (s *Server) GetGroup(ctx context.Context, req GetGroupRequestObject) (GetGroupResponseObject, error) {
	g, err := s.ids.GetGroup(ctx, req.TenantId, req.GroupId)
	if err != nil {
		return nil, err
	}
	res, err := s.groupResponse(ctx, g)
	return GetGroup200JSONResponse{res}, err
}

func (s *Server) UpdateGroup(ctx context.Context, req UpdateGroupRequestObject) (UpdateGroupResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" {
		return nil, badRequest("name is required")
	}
	g, err := s.ids.UpdateGroup(ctx, req.TenantId, req.GroupId, version, req.Body.Name)
	if err != nil {
		return nil, err
	}
	res, err := s.groupResponse(ctx, g)
	return UpdateGroup200JSONResponse{res}, err
}

func (s *Server) DeleteGroup(ctx context.Context, req DeleteGroupRequestObject) (DeleteGroupResponseObject, error) {
	if err := s.ids.DeleteGroup(ctx, req.TenantId, req.GroupId); err != nil {
		return nil, err
	}
	return DeleteGroup204Response{}, nil
}

func (s *Server) ListGroupMembers(ctx context.Context, req ListGroupMembersRequestObject) (ListGroupMembersResponseObject, error) {
	users, nextTok, err := s.ids.ListGroupMembers(ctx, req.TenantId, req.GroupId, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListGroupMembers200JSONResponse{Items: []User{}, NextPageToken: next(nextTok)}
	for _, u := range users {
		dto, err := s.userDTO(ctx, u)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, dto)
	}
	return out, nil
}

func (s *Server) AddGroupMember(ctx context.Context, req AddGroupMemberRequestObject) (AddGroupMemberResponseObject, error) {
	if err := s.ids.AddGroupMember(ctx, req.TenantId, req.GroupId, req.UserId); err != nil {
		return nil, err
	}
	return AddGroupMember204Response{}, nil
}

func (s *Server) RemoveGroupMember(ctx context.Context, req RemoveGroupMemberRequestObject) (RemoveGroupMemberResponseObject, error) {
	if err := s.ids.RemoveGroupMember(ctx, req.TenantId, req.GroupId, req.UserId); err != nil {
		return nil, err
	}
	return RemoveGroupMember204Response{}, nil
}

func (s *Server) AssignGroupRole(ctx context.Context, req AssignGroupRoleRequestObject) (AssignGroupRoleResponseObject, error) {
	if err := s.ids.AssignGroupRole(ctx, req.TenantId, req.GroupId, req.RoleId); err != nil {
		return nil, err
	}
	return AssignGroupRole204Response{}, nil
}

func (s *Server) UnassignGroupRole(ctx context.Context, req UnassignGroupRoleRequestObject) (UnassignGroupRoleResponseObject, error) {
	if err := s.ids.UnassignGroupRole(ctx, req.TenantId, req.GroupId, req.RoleId); err != nil {
		return nil, err
	}
	return UnassignGroupRole204Response{}, nil
}

// ---------------------------------------------------------------- roles

func roleDTO(r identity.Role) Role {
	return Role{Id: &r.ID, Name: r.Name, Description: &r.Description, Meta: meta(r.CreatedAt, r.UpdatedAt, r.Version)}
}

func roleResponse(r identity.Role) RoleResponseJSONResponse {
	return RoleResponseJSONResponse{Body: roleDTO(r), Headers: RoleResponseResponseHeaders{ETag: ptr(etag(r.Version))}}
}

func (s *Server) ListRoles(ctx context.Context, req ListRolesRequestObject) (ListRolesResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	rs, nextTok, err := s.ids.ListRoles(ctx, req.TenantId, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListRoles200JSONResponse{Items: []Role{}, NextPageToken: next(nextTok)}
	for _, r := range rs {
		out.Items = append(out.Items, roleDTO(r))
	}
	return out, nil
}

func (s *Server) CreateRole(ctx context.Context, req CreateRoleRequestObject) (CreateRoleResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" {
		return nil, badRequest("name is required")
	}
	r, err := s.ids.CreateRole(ctx, req.TenantId, req.Body.Name, str(req.Body.Description))
	if err != nil {
		return nil, err
	}
	return CreateRole201JSONResponse{roleResponse(r)}, nil
}

func (s *Server) GetRole(ctx context.Context, req GetRoleRequestObject) (GetRoleResponseObject, error) {
	r, err := s.ids.GetRole(ctx, req.TenantId, req.RoleId)
	if err != nil {
		return nil, err
	}
	return GetRole200JSONResponse{roleResponse(r)}, nil
}

func (s *Server) UpdateRole(ctx context.Context, req UpdateRoleRequestObject) (UpdateRoleResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" {
		return nil, badRequest("name is required")
	}
	r, err := s.ids.UpdateRole(ctx, req.TenantId, req.RoleId, version, req.Body.Name, str(req.Body.Description))
	if err != nil {
		return nil, err
	}
	return UpdateRole200JSONResponse{roleResponse(r)}, nil
}

func (s *Server) DeleteRole(ctx context.Context, req DeleteRoleRequestObject) (DeleteRoleResponseObject, error) {
	if err := s.ids.DeleteRole(ctx, req.TenantId, req.RoleId); err != nil {
		return nil, err
	}
	return DeleteRole204Response{}, nil
}

// ---------------------------------------------------------------- clients

func clientDTO(c oidc.Client) Client {
	gts := make([]ClientGrantTypes, len(c.GrantTypes))
	for i, g := range c.GrantTypes {
		gts[i] = ClientGrantTypes(g)
	}
	return Client{Id: &c.ID, ClientId: &c.ClientID, Name: c.Name, ClientType: ClientClientType(c.Type), FirstParty: &c.FirstParty,
		TokenEndpointAuthMethod: ClientTokenEndpointAuthMethod(c.AuthMethod), GrantTypes: gts, RedirectUris: c.RedirectURIs,
		PostLogoutRedirectUris: &c.PostLogoutRedirectURIs, BackchannelLogoutUri: c.BackchannelLogoutURI, AllowedScopes: &c.AllowedScopes,
		AccessTokenFormat: ptr(ClientAccessTokenFormat(c.AccessTokenFormat)), Meta: meta(c.CreatedAt, c.UpdatedAt, c.Version)}
}

func clientResponse(c oidc.Client) ClientResponseJSONResponse {
	return ClientResponseJSONResponse{Body: clientDTO(c), Headers: ClientResponseResponseHeaders{ETag: ptr(etag(c.Version))}}
}

func (s *Server) ListClients(ctx context.Context, req ListClientsRequestObject) (ListClientsResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	cs, nextTok, err := s.clients.List(ctx, req.TenantId, pageSize(req.Params.PageSize), str(req.Params.PageToken))
	if err != nil {
		return nil, err
	}
	out := ListClients200JSONResponse{Items: []Client{}, NextPageToken: next(nextTok)}
	for _, c := range cs {
		out.Items = append(out.Items, clientDTO(c))
	}
	return out, nil
}

func (s *Server) CreateClient(ctx context.Context, req CreateClientRequestObject) (CreateClientResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil || b.Name == "" || len(b.GrantTypes) == 0 {
		return nil, badRequest("name, client_type and grant_types are required")
	}
	nc := oidc.NewClient{Name: b.Name, Type: oidc.ClientType(b.ClientType), BackchannelLogoutURI: b.BackchannelLogoutUri}
	if nc.Type != oidc.Confidential && nc.Type != oidc.Public {
		return nil, badRequest("client_type must be confidential or public")
	}
	for _, g := range b.GrantTypes {
		nc.GrantTypes = append(nc.GrantTypes, string(g))
	}
	if b.FirstParty != nil {
		nc.FirstParty = *b.FirstParty
	}
	if b.TokenEndpointAuthMethod != nil {
		nc.AuthMethod = oidc.AuthMethod(*b.TokenEndpointAuthMethod)
	}
	if b.RedirectUris != nil {
		nc.RedirectURIs = *b.RedirectUris
	}
	if b.PostLogoutRedirectUris != nil {
		nc.PostLogoutRedirectURIs = *b.PostLogoutRedirectUris
	}
	if b.AllowedScopes != nil {
		nc.AllowedScopes = *b.AllowedScopes
	}
	if b.AccessTokenFormat != nil {
		nc.AccessTokenFormat = string(*b.AccessTokenFormat)
	}
	c, secret, err := s.clients.Create(ctx, req.TenantId, nc)
	if err != nil {
		return nil, err
	}
	dto := clientDTO(c)
	res := CreateClient201JSONResponse{Headers: CreateClient201ResponseHeaders{ETag: ptr(etag(c.Version))}}
	raw, _ := json.Marshal(dto)
	json.Unmarshal(raw, &res.Body)
	res.Body.ClientSecret = strPtr(secret)
	return res, nil
}

func (s *Server) GetClient(ctx context.Context, req GetClientRequestObject) (GetClientResponseObject, error) {
	c, err := s.clients.Get(ctx, req.TenantId, req.ClientId)
	if err != nil {
		return nil, err
	}
	return GetClient200JSONResponse{clientResponse(c)}, nil
}

func (s *Server) UpdateClient(ctx context.Context, req UpdateClientRequestObject) (UpdateClientResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, badRequest("body is required")
	}
	p := oidc.ClientPatch{Name: b.Name, FirstParty: b.FirstParty, RedirectURIs: b.RedirectUris,
		PostLogoutRedirectURIs: b.PostLogoutRedirectUris, AllowedScopes: b.AllowedScopes, BackchannelLogoutURI: &b.BackchannelLogoutUri}
	if b.AccessTokenFormat != nil {
		p.AccessTokenFormat = ptr(string(*b.AccessTokenFormat))
	}
	c, err := s.clients.Update(ctx, req.TenantId, req.ClientId, version, p)
	if err != nil {
		return nil, err
	}
	return UpdateClient200JSONResponse{clientResponse(c)}, nil
}

func (s *Server) DeleteClient(ctx context.Context, req DeleteClientRequestObject) (DeleteClientResponseObject, error) {
	if err := s.clients.Delete(ctx, req.TenantId, req.ClientId); err != nil {
		return nil, err
	}
	return DeleteClient204Response{}, nil
}

func (s *Server) ListClientSecrets(ctx context.Context, req ListClientSecretsRequestObject) (ListClientSecretsResponseObject, error) {
	secs, err := s.clients.ListSecrets(ctx, req.TenantId, req.ClientId)
	if err != nil {
		return nil, err
	}
	out := ListClientSecrets200JSONResponse{Items: []ClientSecret{}}
	for _, sec := range secs {
		out.Items = append(out.Items, ClientSecret{Id: sec.ID, CreatedAt: sec.CreatedAt, ExpiresAt: sec.ExpiresAt})
	}
	return out, nil
}

func (s *Server) CreateClientSecret(ctx context.Context, req CreateClientSecretRequestObject) (CreateClientSecretResponseObject, error) {
	var exp *time.Time
	if req.Body != nil {
		exp = req.Body.ExpiresAt
	}
	sec, plain, err := s.clients.AddSecret(ctx, req.TenantId, req.ClientId, exp)
	if errors.Is(err, oidc.ErrClientConflict) {
		return nil, apiError{http.StatusConflict, "public clients have no secrets"}
	}
	if err != nil {
		return nil, err
	}
	return CreateClientSecret201JSONResponse{Id: sec.ID, CreatedAt: sec.CreatedAt, ExpiresAt: sec.ExpiresAt, Secret: &plain}, nil
}

func (s *Server) DeleteClientSecret(ctx context.Context, req DeleteClientSecretRequestObject) (DeleteClientSecretResponseObject, error) {
	if err := s.clients.DeleteSecret(ctx, req.TenantId, req.ClientId, req.SecretId); err != nil {
		return nil, err
	}
	return DeleteClientSecret204Response{}, nil
}

// ---------------------------------------------------------------- identity providers

func idpDTO(p federation.IdentityProvider) IdentityProvider {
	return IdentityProvider{Id: &p.ID, Name: p.Name, Type: IdentityProviderType(p.Type), Issuer: p.Issuer, ClientId: p.ClientID,
		Scopes: p.Scopes, AllowSignup: p.AllowSignup, Meta: meta(p.CreatedAt, p.UpdatedAt, p.Version)}
}

func idpResponse(p federation.IdentityProvider) IdentityProviderResponseJSONResponse {
	return IdentityProviderResponseJSONResponse{Body: idpDTO(p), Headers: IdentityProviderResponseResponseHeaders{ETag: ptr(etag(p.Version))}}
}

func idpInput(b *IdentityProviderWrite) federation.IdentityProviderInput {
	in := federation.IdentityProviderInput{Name: b.Name, Issuer: b.Issuer, ClientID: b.ClientId, ClientSecret: b.ClientSecret}
	if b.Scopes != nil {
		in.Scopes = *b.Scopes
	}
	if b.AllowSignup != nil {
		in.AllowSignup = *b.AllowSignup
	}
	return in
}

func (s *Server) ListIdentityProviders(ctx context.Context, req ListIdentityProvidersRequestObject) (ListIdentityProvidersResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	ps, err := s.fed.ListIdPs(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	out := ListIdentityProviders200JSONResponse{Items: []IdentityProvider{}}
	for _, p := range ps {
		out.Items = append(out.Items, idpDTO(p))
	}
	return out, nil
}

func (s *Server) CreateIdentityProvider(ctx context.Context, req CreateIdentityProviderRequestObject) (CreateIdentityProviderResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("body is required")
	}
	p, err := s.fed.CreateIdP(ctx, req.TenantId, idpInput(req.Body))
	if err != nil {
		return nil, err
	}
	return CreateIdentityProvider201JSONResponse{idpResponse(p)}, nil
}

func (s *Server) GetIdentityProvider(ctx context.Context, req GetIdentityProviderRequestObject) (GetIdentityProviderResponseObject, error) {
	p, err := s.fed.GetIdP(ctx, req.TenantId, req.ProviderId)
	if err != nil {
		return nil, err
	}
	return GetIdentityProvider200JSONResponse{idpResponse(p)}, nil
}

func (s *Server) UpdateIdentityProvider(ctx context.Context, req UpdateIdentityProviderRequestObject) (UpdateIdentityProviderResponseObject, error) {
	version, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("body is required")
	}
	p, err := s.fed.UpdateIdP(ctx, req.TenantId, req.ProviderId, version, idpInput(req.Body))
	if errors.Is(err, federation.ErrConflict) {
		return nil, errPrecondition
	}
	if err != nil {
		return nil, err
	}
	return UpdateIdentityProvider200JSONResponse{idpResponse(p)}, nil
}

func (s *Server) DeleteIdentityProvider(ctx context.Context, req DeleteIdentityProviderRequestObject) (DeleteIdentityProviderResponseObject, error) {
	if err := s.fed.DeleteIdP(ctx, req.TenantId, req.ProviderId); err != nil {
		return nil, err
	}
	return DeleteIdentityProvider204Response{}, nil
}

// ---------------------------------------------------------------- SAML service providers

func (s *Server) ListSamlServiceProviders(ctx context.Context, req ListSamlServiceProvidersRequestObject) (ListSamlServiceProvidersResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	sps, err := s.fed.ListSAMLSPs(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	out := ListSamlServiceProviders200JSONResponse{Items: []SamlServiceProvider{}}
	for _, sp := range sps {
		out.Items = append(out.Items, SamlServiceProvider{Id: sp.ID, EntityId: sp.EntityID, CreatedAt: sp.CreatedAt})
	}
	return out, nil
}

func (s *Server) CreateSamlServiceProvider(ctx context.Context, req CreateSamlServiceProviderRequestObject) (CreateSamlServiceProviderResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("metadata_xml is required")
	}
	sp, err := s.fed.CreateSAMLSP(ctx, req.TenantId, req.Body.MetadataXml)
	if err != nil {
		return nil, err
	}
	return CreateSamlServiceProvider201JSONResponse{Id: sp.ID, EntityId: sp.EntityID, CreatedAt: sp.CreatedAt}, nil
}

func (s *Server) DeleteSamlServiceProvider(ctx context.Context, req DeleteSamlServiceProviderRequestObject) (DeleteSamlServiceProviderResponseObject, error) {
	if err := s.fed.DeleteSAMLSP(ctx, req.TenantId, req.SpId); err != nil {
		return nil, err
	}
	return DeleteSamlServiceProvider204Response{}, nil
}

// ---------------------------------------------------------------- signing keys

func (s *Server) keyList(ctx context.Context, tenantID uuid.UUID) ([]SigningKey, error) {
	ks, err := s.keys.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := []SigningKey{}
	for _, k := range ks {
		var jwk map[string]any
		raw, _ := json.Marshal(k.PublicJWK)
		json.Unmarshal(raw, &jwk)
		out = append(out, SigningKey{Kid: k.KID, Alg: SigningKeyAlg(k.Alg), Status: SigningKeyStatus(k.Status), PublicJwk: jwk,
			CreatedAt: k.CreatedAt, ActivatedAt: k.ActivatedAt, RetiredAt: k.RetiredAt})
	}
	return out, nil
}

func (s *Server) ListSigningKeys(ctx context.Context, req ListSigningKeysRequestObject) (ListSigningKeysResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	items, err := s.keyList(ctx, req.TenantId)
	return ListSigningKeys200JSONResponse{Items: items}, err
}

func (s *Server) RotateSigningKeys(ctx context.Context, req RotateSigningKeysRequestObject) (RotateSigningKeysResponseObject, error) {
	t, err := s.tenant(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	if err := s.keys.Rotate(ctx, t.ID); err != nil {
		return nil, err
	}
	maxLifetime := max(t.Settings.AccessTokenTTL(), t.Settings.IDTokenTTL())
	if err := s.keys.RetireExpired(ctx, t.ID, maxLifetime); err != nil {
		return nil, err
	}
	items, err := s.keyList(ctx, t.ID)
	return RotateSigningKeys200JSONResponse{Items: items}, err
}

// ---------------------------------------------------------------- webhooks

func webhookDTO(e audit.WebhookEndpoint) WebhookEndpoint {
	types := make([]EventType, len(e.EventTypes))
	for i, t := range e.EventTypes {
		types[i] = EventType(t)
	}
	return WebhookEndpoint{Id: &e.ID, Url: e.URL, EventTypes: types, Enabled: e.Enabled}
}

func eventTypes(in *[]EventType) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(*in))
	for i, t := range *in {
		out[i] = string(t)
	}
	return out
}

func (s *Server) ListWebhookEndpoints(ctx context.Context, req ListWebhookEndpointsRequestObject) (ListWebhookEndpointsResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	es, err := s.webhooks.List(ctx, req.TenantId)
	if err != nil {
		return nil, err
	}
	out := ListWebhookEndpoints200JSONResponse{Items: []WebhookEndpoint{}}
	for _, e := range es {
		out.Items = append(out.Items, webhookDTO(e))
	}
	return out, nil
}

func (s *Server) CreateWebhookEndpoint(ctx context.Context, req CreateWebhookEndpointRequestObject) (CreateWebhookEndpointResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Url == nil || *req.Body.Url == "" {
		return nil, badRequest("url is required")
	}
	e, secret, err := s.webhooks.Create(ctx, req.TenantId, *req.Body.Url, eventTypes(req.Body.EventTypes))
	if err != nil {
		return nil, err
	}
	dto := webhookDTO(e)
	return CreateWebhookEndpoint201JSONResponse{Id: dto.Id, Url: dto.Url, EventTypes: dto.EventTypes, Enabled: dto.Enabled, Secret: &secret}, nil
}

func (s *Server) GetWebhookEndpoint(ctx context.Context, req GetWebhookEndpointRequestObject) (GetWebhookEndpointResponseObject, error) {
	e, err := s.webhooks.Get(ctx, req.TenantId, req.EndpointId)
	if err != nil {
		return nil, err
	}
	return GetWebhookEndpoint200JSONResponse(webhookDTO(e)), nil
}

func (s *Server) UpdateWebhookEndpoint(ctx context.Context, req UpdateWebhookEndpointRequestObject) (UpdateWebhookEndpointResponseObject, error) {
	if req.Body == nil {
		return nil, badRequest("body is required")
	}
	var types *[]string
	if req.Body.EventTypes != nil {
		t := eventTypes(req.Body.EventTypes)
		types = &t
	}
	e, err := s.webhooks.Update(ctx, req.TenantId, req.EndpointId, req.Body.Url, types, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return UpdateWebhookEndpoint200JSONResponse(webhookDTO(e)), nil
}

func (s *Server) DeleteWebhookEndpoint(ctx context.Context, req DeleteWebhookEndpointRequestObject) (DeleteWebhookEndpointResponseObject, error) {
	if err := s.webhooks.Delete(ctx, req.TenantId, req.EndpointId); err != nil {
		return nil, err
	}
	return DeleteWebhookEndpoint204Response{}, nil
}

// ---------------------------------------------------------------- audit logs

func (s *Server) ListAuditLogs(ctx context.Context, req ListAuditLogsRequestObject) (ListAuditLogsResponseObject, error) {
	if _, err := s.tenant(ctx, req.TenantId); err != nil {
		return nil, err
	}
	p := req.Params
	f := audit.LogFilter{From: p.From, To: p.To, ActorID: str(p.ActorId), Action: str(p.Action)}
	if p.Result != nil {
		f.Result = string(*p.Result)
	}
	logs, nextTok, err := s.relay.ListAuditLogs(ctx, req.TenantId, f, pageSize(p.PageSize), str(p.PageToken))
	if err != nil {
		return nil, badRequest("invalid query")
	}
	out := ListAuditLogs200JSONResponse{Items: []AuditLog{}, NextPageToken: next(nextTok)}
	for _, l := range logs {
		details := l.Details
		out.Items = append(out.Items, AuditLog{Seq: l.Seq, EventId: l.EventID, OccurredAt: l.OccurredAt,
			Actor: Actor{Type: ActorType(l.ActorType), Id: l.ActorID}, Action: l.Action,
			Target: &struct {
				Id   *string `json:"id,omitempty"`
				Type *string `json:"type,omitempty"`
			}{Id: &l.TargetID, Type: &l.TargetType},
			Result: AuditLogResult(l.Result), Ip: &l.IP, UserAgent: &l.UserAgent, Details: &details})
	}
	return out, nil
}
