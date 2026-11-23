// Package scim implements SCIM 2.0 (RFC 7643 / RFC 7644) Users and Groups
// provisioning on top of the identity module. It is served per tenant at
// /t/{tenant}/scim/v2 and authenticated with Admin API tokens.
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/oidc"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/web"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	contentType = "application/scim+json"
	// AdminTenantSlug must match adminapi.AdminTenantSlug.
	AdminTenantSlug = "admin"
)

type Server struct {
	s *web.Server
}

func New() *Server { return &Server{} }

func (x *Server) Routes(mux *http.ServeMux, s *web.Server) {
	x.s = s
	r := func(pattern string, h func(http.ResponseWriter, *http.Request, identity.Tenant)) {
		method, path, _ := strings.Cut(pattern, " ")
		s.Tenant(mux, method+" /scim/v2"+path, x.auth(h))
	}
	r("GET /ServiceProviderConfig", x.config)
	r("GET /Users", x.listUsers)
	r("POST /Users", x.createUser)
	r("GET /Users/{id}", x.getUser)
	r("PUT /Users/{id}", x.replaceUser)
	r("PATCH /Users/{id}", x.patchUser)
	r("DELETE /Users/{id}", x.deleteUser)
	r("GET /Groups", x.listGroups)
	r("POST /Groups", x.createGroup)
	r("GET /Groups/{id}", x.getGroup)
	r("PATCH /Groups/{id}", x.patchGroup)
	r("DELETE /Groups/{id}", x.deleteGroup)
}

// ---------------------------------------------------------------- plumbing

func (x *Server) auth(h func(http.ResponseWriter, *http.Request, identity.Tenant)) func(http.ResponseWriter, *http.Request, identity.Tenant) {
	return func(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
		token := ""
		if v := r.Header.Get("Authorization"); len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			token = v[7:]
		}
		admin, err := x.s.Identity().GetTenantBySlug(r.Context(), AdminTenantSlug)
		if err != nil || token == "" {
			scimError(w, http.StatusUnauthorized, "", "a bearer token is required")
			return
		}
		info, err := x.s.Provider().AuthenticateBearer(r.Context(), admin, token)
		if err != nil {
			scimError(w, http.StatusUnauthorized, "", "invalid token")
			return
		}
		scope := "admin:write"
		if r.Method == http.MethodGet {
			scope = "admin:read"
		}
		if !contains(info.Scopes, scope) {
			scimError(w, http.StatusForbidden, "", "scope "+scope+" is required")
			return
		}
		ctx := audit.WithActor(r.Context(), audit.Actor{Type: audit.ActorAdmin, ID: info.ClientID})
		h(w, r.WithContext(ctx), t)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	write(w, status, body)
}

func (x *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrNotFound):
		scimError(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, identity.ErrConflict):
		scimError(w, http.StatusConflict, "uniqueness", "the resource conflicts with an existing one")
	case errors.Is(err, errInvalid):
		scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
	case errors.Is(err, errFilter):
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
	default:
		x.s.InternalError(w, r, err)
	}
}

var (
	errInvalid = errors.New("invalid value")
	errFilter  = errors.New("unsupported filter")
)

func (x *Server) location(t identity.Tenant, kind, id string) string {
	return x.s.BaseURL() + x.s.TenantBase(t) + "/scim/v2/" + kind + "/" + id
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, identity.ErrNotFound
	}
	return id, nil
}

var eqFilter = regexp.MustCompile(`^\s*(\w+)\s+eq\s+"([^"]*)"\s*$`)

// parseEq supports the "attr eq "value"" filter (the subset provisioning
// clients use to look up existing resources).
func parseEq(f string, allowed ...string) (string, string, error) {
	if f == "" {
		return "", "", nil
	}
	m := eqFilter.FindStringSubmatch(f)
	if m == nil || !contains(allowed, m[1]) {
		return "", "", errFilter
	}
	return m[1], m[2], nil
}

func listResponse(items []any) map[string]any {
	return map[string]any{"schemas": []string{schemaList}, "totalResults": len(items), "startIndex": 1, "itemsPerPage": len(items), "Resources": items}
}

func (x *Server) config(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	write(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": true},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "OAuth Bearer Token",
			"description": "Admin API access token (client credentials at the admin tenant)"}},
	})
}

// ---------------------------------------------------------------- users

type scimUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Name     *struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Active *bool `json:"active"`
}

func (u scimUser) email() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

func (x *Server) userResource(t identity.Tenant, u identity.User) map[string]any {
	return map[string]any{
		"schemas": []string{schemaUser}, "id": u.ID.String(), "userName": u.LoginID,
		"name":   map[string]string{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.Name()},
		"emails": []map[string]any{{"value": u.Email, "primary": true}}, "active": u.Status == identity.StatusActive,
		"meta": map[string]any{"resourceType": "User", "created": u.CreatedAt.Format(time.RFC3339), "lastModified": u.UpdatedAt.Format(time.RFC3339),
			"location": x.location(t, "Users", u.ID.String()), "version": `W/"` + strconv.FormatInt(u.Version, 10) + `"`},
	}
}

func (x *Server) listUsers(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	attr, val, err := parseEq(r.URL.Query().Get("filter"), "userName", "emails")
	if err != nil {
		x.fail(w, r, err)
		return
	}
	f := identity.UserFilter{}
	if attr == "userName" {
		f.LoginID = val
	} else if attr == "emails" {
		f.Email = val
	}
	users, _, err := x.s.Identity().ListUsers(r.Context(), t.ID, f, 200, "")
	if err != nil {
		x.fail(w, r, err)
		return
	}
	items := make([]any, len(users))
	for i, u := range users {
		items[i] = x.userResource(t, u)
	}
	write(w, http.StatusOK, listResponse(items))
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errInvalid
	}
	return nil
}

func (x *Server) createUser(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	var in scimUser
	if err := decode(r, &in); err != nil || in.UserName == "" || in.email() == "" {
		x.fail(w, r, errInvalid)
		return
	}
	nu := identity.NewUser{LoginID: in.UserName, Email: in.email()}
	if in.Name != nil {
		nu.GivenName, nu.FamilyName = in.Name.GivenName, in.Name.FamilyName
	}
	u, err := x.s.Identity().CreateUserAudited(r.Context(), t.ID, nu)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	if in.Active != nil && !*in.Active {
		if err := x.setActive(r.Context(), t, u.ID, false); err != nil {
			x.fail(w, r, err)
			return
		}
		u, _ = x.s.Identity().GetUser(r.Context(), t.ID, u.ID)
	}
	w.Header().Set("Location", x.location(t, "Users", u.ID.String()))
	write(w, http.StatusCreated, x.userResource(t, u))
}

func (x *Server) getUser(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err == nil {
		var u identity.User
		if u, err = x.s.Identity().GetUser(r.Context(), t.ID, id); err == nil {
			write(w, http.StatusOK, x.userResource(t, u))
			return
		}
	}
	x.fail(w, r, err)
}

// setActive maps SCIM "active" to the user status; deactivation revokes
// sessions and tokens.
func (x *Server) setActive(ctx context.Context, t identity.Tenant, id uuid.UUID, active bool) error {
	st := identity.StatusDisabled
	if active {
		st = identity.StatusActive
	}
	return postgres.InTx(ctx, x.s.Identity().Pool(), func(tx pgx.Tx) error {
		if err := x.s.Identity().SetStatusAudited(ctx, tx, t.ID, id, st); err != nil {
			return err
		}
		if active {
			return nil
		}
		if err := authn.RevokeUserSessionsTx(ctx, tx, t.ID, id, time.Now()); err != nil {
			return err
		}
		return oidc.RevokeUserTokensTx(ctx, tx, t.ID, id)
	})
}

func (x *Server) replaceUser(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	var in scimUser
	if err := decode(r, &in); err != nil || in.UserName == "" {
		x.fail(w, r, errInvalid)
		return
	}
	p := identity.UserPatch{LoginID: &in.UserName}
	if e := in.email(); e != "" {
		p.Email = &e
	}
	if in.Name != nil {
		p.GivenName, p.FamilyName = &in.Name.GivenName, &in.Name.FamilyName
	}
	x.update(w, r, t, id, p, in.Active)
}

func (x *Server) update(w http.ResponseWriter, r *http.Request, t identity.Tenant, id uuid.UUID, p identity.UserPatch, active *bool) {
	ctx := r.Context()
	u, err := x.s.Identity().UpdateUser(ctx, t.ID, id, 0, p)
	if err == nil && active != nil && *active != (u.Status == identity.StatusActive) {
		if err = x.setActive(ctx, t, id, *active); err == nil {
			u, err = x.s.Identity().GetUser(ctx, t.ID, id)
		}
	}
	if err != nil {
		x.fail(w, r, err)
		return
	}
	write(w, http.StatusOK, x.userResource(t, u))
}

type patchOp struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

func (x *Server) patchUser(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	var in patchOp
	if err := decode(r, &in); err != nil {
		x.fail(w, r, err)
		return
	}
	var p identity.UserPatch
	var active *bool
	set := func(path string, raw json.RawMessage) error {
		var s string
		switch path {
		case "active":
			var b bool
			if json.Unmarshal(raw, &b) != nil {
				return errInvalid
			}
			active = &b
			return nil
		case "userName":
			if json.Unmarshal(raw, &s) != nil {
				return errInvalid
			}
			p.LoginID = &s
		case "name.givenName":
			if json.Unmarshal(raw, &s) != nil {
				return errInvalid
			}
			p.GivenName = &s
		case "name.familyName":
			if json.Unmarshal(raw, &s) != nil {
				return errInvalid
			}
			p.FamilyName = &s
		default:
			return errInvalid
		}
		return nil
	}
	for _, op := range in.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			x.fail(w, r, errInvalid)
			return
		}
		if op.Path == "" { // value is an object of attributes
			var attrs map[string]json.RawMessage
			if json.Unmarshal(op.Value, &attrs) != nil {
				x.fail(w, r, errInvalid)
				return
			}
			for k, v := range attrs {
				if err := set(k, v); err != nil {
					x.fail(w, r, err)
					return
				}
			}
			continue
		}
		if err := set(op.Path, op.Value); err != nil {
			x.fail(w, r, err)
			return
		}
	}
	x.update(w, r, t, id, p, active)
}

func (x *Server) deleteUser(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err == nil {
		err = postgres.InTx(r.Context(), x.s.Identity().Pool(), func(tx pgx.Tx) error { return oidc.RevokeUserTokensTx(r.Context(), tx, t.ID, id) })
	}
	if err == nil {
		err = x.s.Identity().SoftDeleteUser(r.Context(), t.ID, id)
	}
	if err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- groups

func (x *Server) groupResource(ctx context.Context, t identity.Tenant, g identity.Group) (map[string]any, error) {
	members, _, err := x.s.Identity().ListGroupMembers(ctx, t.ID, g.ID, 1000, "")
	if err != nil {
		return nil, err
	}
	ms := make([]map[string]string, len(members))
	for i, m := range members {
		ms[i] = map[string]string{"value": m.ID.String(), "display": m.LoginID, "$ref": x.location(t, "Users", m.ID.String())}
	}
	return map[string]any{"schemas": []string{schemaGroup}, "id": g.ID.String(), "displayName": g.Name, "members": ms,
		"meta": map[string]any{"resourceType": "Group", "created": g.CreatedAt.Format(time.RFC3339), "lastModified": g.UpdatedAt.Format(time.RFC3339),
			"location": x.location(t, "Groups", g.ID.String()), "version": `W/"` + strconv.FormatInt(g.Version, 10) + `"`}}, nil
}

func (x *Server) writeGroup(w http.ResponseWriter, r *http.Request, t identity.Tenant, status int, g identity.Group) {
	res, err := x.groupResource(r.Context(), t, g)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	write(w, status, res)
}

func (x *Server) listGroups(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	attr, val, err := parseEq(r.URL.Query().Get("filter"), "displayName")
	if err != nil {
		x.fail(w, r, err)
		return
	}
	groups, _, err := x.s.Identity().ListGroups(r.Context(), t.ID, 1000, "")
	if err != nil {
		x.fail(w, r, err)
		return
	}
	items := []any{}
	for _, g := range groups {
		if attr != "" && g.Name != val {
			continue
		}
		res, err := x.groupResource(r.Context(), t, g)
		if err != nil {
			x.fail(w, r, err)
			return
		}
		items = append(items, res)
	}
	write(w, http.StatusOK, listResponse(items))
}

type member struct {
	Value string `json:"value"`
}

func (x *Server) addMembers(ctx context.Context, t identity.Tenant, gid uuid.UUID, ms []member) error {
	for _, m := range ms {
		uid, err := uuid.Parse(m.Value)
		if err != nil {
			return errInvalid
		}
		if err := x.s.Identity().AddGroupMember(ctx, t.ID, gid, uid); err != nil {
			return err
		}
	}
	return nil
}

func (x *Server) createGroup(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	var in struct {
		DisplayName string   `json:"displayName"`
		Members     []member `json:"members"`
	}
	if err := decode(r, &in); err != nil || in.DisplayName == "" {
		x.fail(w, r, errInvalid)
		return
	}
	g, err := x.s.Identity().CreateGroup(r.Context(), t.ID, in.DisplayName)
	if err == nil {
		err = x.addMembers(r.Context(), t, g.ID, in.Members)
	}
	if err != nil {
		x.fail(w, r, err)
		return
	}
	w.Header().Set("Location", x.location(t, "Groups", g.ID.String()))
	x.writeGroup(w, r, t, http.StatusCreated, g)
}

func (x *Server) getGroup(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err == nil {
		var g identity.Group
		if g, err = x.s.Identity().GetGroup(r.Context(), t.ID, id); err == nil {
			x.writeGroup(w, r, t, http.StatusOK, g)
			return
		}
	}
	x.fail(w, r, err)
}

var memberPath = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func (x *Server) patchGroup(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	ctx := r.Context()
	id, err := pathID(r)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	g, err := x.s.Identity().GetGroup(ctx, t.ID, id)
	if err != nil {
		x.fail(w, r, err)
		return
	}
	var in patchOp
	if err := decode(r, &in); err != nil {
		x.fail(w, r, err)
		return
	}
	for _, op := range in.Operations {
		switch strings.ToLower(op.Op) {
		case "add":
			var ms []member
			if op.Path != "members" || json.Unmarshal(op.Value, &ms) != nil {
				x.fail(w, r, errInvalid)
				return
			}
			err = x.addMembers(ctx, t, id, ms)
		case "remove":
			var ids []string
			if m := memberPath.FindStringSubmatch(op.Path); m != nil {
				ids = []string{m[1]}
			} else if op.Path == "members" {
				var ms []member
				json.Unmarshal(op.Value, &ms)
				for _, m := range ms {
					ids = append(ids, m.Value)
				}
			} else {
				err = errInvalid
			}
			for _, s := range ids {
				uid, perr := uuid.Parse(s)
				if perr != nil {
					err = errInvalid
					break
				}
				if err = x.s.Identity().RemoveGroupMember(ctx, t.ID, id, uid); err != nil {
					break
				}
			}
		case "replace":
			var name string
			if op.Path == "displayName" && json.Unmarshal(op.Value, &name) == nil && name != "" {
				g, err = x.s.Identity().UpdateGroup(ctx, t.ID, id, 0, name)
			} else {
				err = errInvalid
			}
		default:
			err = errInvalid
		}
		if err != nil {
			x.fail(w, r, err)
			return
		}
	}
	x.writeGroup(w, r, t, http.StatusOK, g)
}

func (x *Server) deleteGroup(w http.ResponseWriter, r *http.Request, t identity.Tenant) {
	id, err := pathID(r)
	if err == nil {
		err = x.s.Identity().DeleteGroup(r.Context(), t.ID, id)
	}
	if err != nil {
		x.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
