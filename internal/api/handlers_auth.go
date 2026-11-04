package api

import (
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/auth"
	"github.com/GoToolSharing/nety/internal/config"
	"github.com/GoToolSharing/nety/internal/model"
)

type sessionResponse struct {
	User      model.User `json:"user"`
	CSRFToken string     `json:"csrf_token"`
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		a.fail(w, http.StatusBadRequest, "invalid", "username and password are required")
		return
	}

	user, err := a.Auth.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			a.Store.Audit(r.Context(), 0, req.Username, 0, "login.locked", "", a.clientIP(r))
			a.fail(w, http.StatusTooManyRequests, "locked", err.Error())
		case errors.Is(err, auth.ErrAccountDisabled):
			a.fail(w, http.StatusForbidden, "disabled", err.Error())
		default:
			a.Store.Audit(r.Context(), 0, req.Username, 0, "login.failed", "", a.clientIP(r))
			a.fail(w, http.StatusUnauthorized, "unauthorized", "invalid username or password")
		}
		return
	}

	token, expires, err := a.Auth.StartSession(r.Context(), user.ID, r.UserAgent(), a.clientIP(r))
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", "cannot start a session")
		return
	}
	csrf, err := auth.GenerateToken()
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", "cannot start a session")
		return
	}
	a.setCookie(w, sessionCookie, token, expires, true)
	a.setCookie(w, csrfCookie, csrf, expires, false)
	a.Store.Audit(r.Context(), user.ID, user.Username, 0, "login", "", a.clientIP(r))
	a.ok(w, sessionResponse{User: user, CSRFToken: csrf})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if user, err := a.Auth.ResolveSession(r.Context(), c.Value); err == nil {
			a.Store.Audit(r.Context(), user.ID, user.Username, 0, "logout", "", a.clientIP(r))
		}
		_ = a.Auth.EndSession(r.Context(), c.Value)
	}
	a.clearCookies(w)
	a.ok(w, map[string]bool{"ok": true})
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	csrf := ""
	if c, err := r.Cookie(csrfCookie); err == nil {
		csrf = c.Value
	}
	if csrf == "" {
		// The session survived a browser restart that dropped the non-persistent
		// CSRF cookie; issue a fresh one rather than forcing a re-login.
		if t, err := auth.GenerateToken(); err == nil {
			csrf = t
			a.setCookie(w, csrfCookie, csrf, time.Now().Add(a.Config.SessionTTL), false)
		}
	}
	a.ok(w, sessionResponse{User: user, CSRFToken: csrf})
}

func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request, u model.User) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := a.Auth.ChangePassword(r.Context(), u.ID, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			a.fail(w, http.StatusForbidden, "forbidden", "current password is incorrect")
		case errors.Is(err, auth.ErrWeakPassword):
			a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		default:
			a.fail(w, http.StatusInternalServerError, "internal", "cannot change the password")
		}
		return
	}
	a.clearCookies(w)
	a.audit(r, u, 0, "password.changed", "")
	a.ok(w, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request, _ model.User) {
	users, err := a.Store.ListUsers(r.Context())
	if err != nil {
		a.failStore(w, err, "users")
		return
	}
	a.ok(w, users)
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request, actor model.User) {
	var req struct {
		Username    string     `json:"username"`
		DisplayName string     `json:"display_name"`
		Role        model.Role `json:"role"`
		Password    string     `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		a.fail(w, http.StatusBadRequest, "invalid", "username is required")
		return
	}
	if req.Role == "" {
		req.Role = model.RoleOperator
	}
	if !auth.ValidRole(req.Role) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown role")
		return
	}
	generated := ""
	if req.Password == "" {
		pw, err := auth.GeneratePassword()
		if err != nil {
			a.fail(w, http.StatusInternalServerError, "internal", "cannot generate a password")
			return
		}
		req.Password, generated = pw, pw
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", "cannot hash the password")
		return
	}
	user, err := a.Store.CreateUser(r.Context(), model.User{
		Username: req.Username, DisplayName: req.DisplayName, Role: req.Role,
		PasswordHash: hash, MustChangePW: true,
	})
	if err != nil {
		a.failStore(w, err, "user")
		return
	}
	a.audit(r, actor, 0, "user.created", user.Username)
	resp := struct {
		model.User
		GeneratedPassword string `json:"generated_password,omitempty"`
	}{User: user, GeneratedPassword: generated}
	a.created(w, resp)
}

func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request, actor model.User) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}
	user, err := a.Store.UserByID(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "user")
		return
	}
	var req struct {
		DisplayName *string     `json:"display_name"`
		Role        *model.Role `json:"role"`
		Disabled    *bool       `json:"disabled"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Role != nil {
		if !auth.ValidRole(*req.Role) {
			a.fail(w, http.StatusBadRequest, "invalid", "unknown role")
			return
		}
		if user.ID == actor.ID && *req.Role != model.RoleAdmin {
			a.fail(w, http.StatusBadRequest, "invalid", "you cannot remove your own administrator role")
			return
		}
		user.Role = *req.Role
	}
	if req.Disabled != nil {
		if user.ID == actor.ID && *req.Disabled {
			a.fail(w, http.StatusBadRequest, "invalid", "you cannot disable your own account")
			return
		}
		user.Disabled = *req.Disabled
	}
	if err := a.Store.UpdateUser(r.Context(), user); err != nil {
		a.failStore(w, err, "user")
		return
	}
	if user.Disabled {
		_ = a.Store.DeleteUserSessions(r.Context(), user.ID)
	}
	a.audit(r, actor, 0, "user.updated", user.Username)
	a.ok(w, user)
}

func (a *API) handleResetPassword(w http.ResponseWriter, r *http.Request, actor model.User) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
		MustChange  *bool  `json:"must_change"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	generated := ""
	if req.NewPassword == "" {
		pw, err := auth.GeneratePassword()
		if err != nil {
			a.fail(w, http.StatusInternalServerError, "internal", "cannot generate a password")
			return
		}
		req.NewPassword, generated = pw, pw
	}
	mustChange := true
	if req.MustChange != nil {
		mustChange = *req.MustChange
	}
	if err := a.Auth.SetPassword(r.Context(), id, req.NewPassword, mustChange); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			a.fail(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		a.failStore(w, err, "user")
		return
	}
	a.audit(r, actor, 0, "user.password_reset", userRef(id))
	a.ok(w, map[string]string{"generated_password": generated})
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request, actor model.User) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}
	if id == actor.ID {
		a.fail(w, http.StatusBadRequest, "invalid", "you cannot delete your own account")
		return
	}
	users, err := a.Store.ListUsers(r.Context())
	if err != nil {
		a.failStore(w, err, "users")
		return
	}
	admins := 0
	var target model.User
	for _, u := range users {
		if u.Role == model.RoleAdmin && !u.Disabled {
			admins++
		}
		if u.ID == id {
			target = u
		}
	}
	if target.ID == 0 {
		a.fail(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if target.Role == model.RoleAdmin && admins <= 1 {
		a.fail(w, http.StatusBadRequest, "invalid", "the last administrator cannot be deleted")
		return
	}
	if err := a.Store.DeleteUser(r.Context(), id); err != nil {
		a.failStore(w, err, "user")
		return
	}
	a.audit(r, actor, 0, "user.deleted", target.Username)
	a.ok(w, map[string]bool{"ok": true})
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request, _ model.User) {
	entries, err := a.Store.AuditLog(r.Context(), queryInt64(r, "mission_id"), queryInt(r, "limit", 200))
	if err != nil {
		a.failStore(w, err, "audit log")
		return
	}
	a.ok(w, entries)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"version":    config.Version,
		"commit":     config.Commit,
		"build_date": config.BuildDate,
		"go":         runtime.Version(),
		"platform":   runtime.GOOS + "/" + runtime.GOARCH,
	}
	// Everything beyond the version requires a session.
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		if _, err := a.Auth.ResolveSession(r.Context(), c.Value); err == nil {
			resp["uptime_seconds"] = int64(time.Since(a.Started).Seconds())
			resp["raw_sockets"] = a.RawCapable
			resp["running_scans"] = a.Runner.Running()
			resp["event_subscribers"] = a.Bus.Subscribers()
			resp["engines"] = map[string]bool{
				"discovery":    a.Engines.Discoverer != nil,
				"portscan":     a.Engines.PortScanner != nil,
				"fingerprint":  a.Engines.Fingerprinter != nil,
				"identity":     a.Engines.Identity != nil,
				"checks":       a.Engines.Checker != nil,
				"netif":        a.Engines.NetInspector != nil,
				"segmentation": a.Engines.Segment != nil,
			}
			if stats, err := a.Store.Stats(r.Context()); err == nil {
				resp["database"] = stats
			}
		}
	}
	a.ok(w, resp)
}

// userRef is how a user is referred to in the audit log when only the id is
// known at that point in the handler.
func userRef(id int64) string { return "user #" + itoa64(id) }

// itoa64 is the decimal form of an id, used all over the audit messages.
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
