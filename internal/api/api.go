// Package api exposes the REST and WebSocket interface of NETY.
//
// Routing uses the standard library's pattern mux. Every handler is small and
// delegates to the store, the auth service or the scan runner.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/auth"
	"github.com/vaadata/nety/internal/bus"
	"github.com/vaadata/nety/internal/config"
	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/export"
	"github.com/vaadata/nety/internal/jobs"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/store"
)

// Cookie names. The session cookie is HttpOnly; the CSRF cookie is readable
// by the SPA so it can echo the value in a header (double-submit pattern).
const (
	sessionCookie = "nety_session"
	csrfCookie    = "nety_csrf"
	csrfHeader    = "X-CSRF-Token"
)

// Deps are everything the API needs.
type Deps struct {
	Store    *store.Store
	Auth     *auth.Service
	Bus      *bus.Bus
	Runner   *jobs.Runner
	Engines  jobs.Engines
	Exporter *export.Exporter
	Config   config.Config
	Log      *slog.Logger
	Started  time.Time
	// RawCapable reports whether the process can open raw sockets, which the
	// UI shows so the operator knows a SYN scan will not silently degrade.
	RawCapable bool
}

// API holds the handlers.
type API struct {
	Deps
	mux *http.ServeMux
}

// New builds the API and registers every route.
func New(d Deps) *API {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Started.IsZero() {
		d.Started = time.Now()
	}
	a := &API{Deps: d, mux: http.NewServeMux()}
	a.routes()
	return a
}

// Handler returns the API handler, already wrapped in its middleware.
func (a *API) Handler() http.Handler {
	return a.recoverer(a.logger(a.mux))
}

func (a *API) routes() {
	// --- public ---
	a.mux.HandleFunc("GET /api/status", a.handleStatus)
	a.mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	a.mux.HandleFunc("POST /api/auth/logout", a.handleLogout)
	a.mux.HandleFunc("GET /api/auth/me", a.handleMe)

	// --- authenticated ---
	auth := a.authenticated
	write := a.writable

	a.mux.Handle("POST /api/auth/password", auth(a.handleChangePassword))

	a.mux.Handle("GET /api/users", a.adminOnly(a.handleListUsers))
	a.mux.Handle("POST /api/users", a.adminOnly(a.handleCreateUser))
	a.mux.Handle("PATCH /api/users/{id}", a.adminOnly(a.handleUpdateUser))
	a.mux.Handle("POST /api/users/{id}/password", a.adminOnly(a.handleResetPassword))
	a.mux.Handle("DELETE /api/users/{id}", a.adminOnly(a.handleDeleteUser))
	a.mux.Handle("GET /api/audit", a.adminOnly(a.handleAudit))

	a.mux.Handle("GET /api/missions", auth(a.handleListMissions))
	a.mux.Handle("POST /api/missions", write(a.handleCreateMission))
	a.mux.Handle("GET /api/missions/{id}", auth(a.handleGetMission))
	a.mux.Handle("PATCH /api/missions/{id}", write(a.handleUpdateMission))
	a.mux.Handle("DELETE /api/missions/{id}", a.adminOnly(a.handleDeleteMission))
	a.mux.Handle("GET /api/missions/{id}/members", auth(a.handleGetMembers))
	a.mux.Handle("PUT /api/missions/{id}/members", a.adminOnly(a.handleSetMembers))
	a.mux.Handle("GET /api/missions/{id}/summary", auth(a.handleMissionSummary))

	a.mux.Handle("GET /api/interfaces", auth(a.handleInterfaces))
	a.mux.Handle("POST /api/networks/detect", write(a.handleDetectNetwork))
	a.mux.Handle("GET /api/missions/{id}/networks", auth(a.handleListNetworks))
	a.mux.Handle("POST /api/missions/{id}/networks", write(a.handleCreateNetwork))
	a.mux.Handle("GET /api/networks/{id}", auth(a.handleGetNetwork))
	a.mux.Handle("PATCH /api/networks/{id}", write(a.handleUpdateNetwork))
	a.mux.Handle("DELETE /api/networks/{id}", write(a.handleDeleteNetwork))

	a.mux.Handle("GET /api/scan-profiles", auth(a.handleScanProfiles))
	a.mux.Handle("GET /api/techniques", auth(a.handleTechniques))
	a.mux.Handle("GET /api/checks", auth(a.handleChecks))
	a.mux.Handle("GET /api/export-formats", auth(a.handleExportFormats))

	a.mux.Handle("GET /api/missions/{id}/scans", auth(a.handleListScans))
	a.mux.Handle("POST /api/missions/{id}/scans", write(a.handleCreateScan))
	a.mux.Handle("GET /api/scans/{id}", auth(a.handleGetScan))
	a.mux.Handle("DELETE /api/scans/{id}", write(a.handleDeleteScan))
	a.mux.Handle("POST /api/scans/{id}/start", write(a.handleStartScan))
	a.mux.Handle("POST /api/scans/{id}/pause", write(a.handlePauseScan))
	a.mux.Handle("POST /api/scans/{id}/stop", write(a.handleStopScan))
	a.mux.Handle("POST /api/scans/{id}/retry-failed", write(a.handleRetryScan))
	a.mux.Handle("GET /api/scans/{id}/logs", auth(a.handleScanLogs))

	a.mux.Handle("GET /api/missions/{id}/hosts", auth(a.handleListHosts))
	a.mux.Handle("GET /api/missions/{id}/services", auth(a.handleListServices))
	a.mux.Handle("GET /api/missions/{id}/findings", auth(a.handleListFindings))
	a.mux.Handle("GET /api/missions/{id}/assets", auth(a.handleListAssets))
	a.mux.Handle("GET /api/missions/{id}/matrix", auth(a.handleMatrix))
	a.mux.Handle("GET /api/missions/{id}/reach", auth(a.handleListReach))
	a.mux.Handle("GET /api/hosts/{id}", auth(a.handleGetHost))
	a.mux.Handle("GET /api/assets/{id}", auth(a.handleGetAsset))
	a.mux.Handle("PATCH /api/assets/{id}", write(a.handleUpdateAsset))
	a.mux.Handle("POST /api/assets/{id}/merge", write(a.handleMergeAssets))

	a.mux.Handle("GET /api/missions/{id}/export", auth(a.handleExport))
	a.mux.Handle("GET /api/missions/{id}/events", auth(a.handleEvents))
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

type ctxKey int

const userKey ctxKey = iota

func userFrom(ctx context.Context) model.User {
	u, _ := ctx.Value(userKey).(model.User)
	return u
}

// handlerFunc is a handler that knows the authenticated user.
type handlerFunc func(w http.ResponseWriter, r *http.Request, u model.User)

// authenticated requires a valid session.
func (a *API) authenticated(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := a.requireSession(w, r)
		if !ok {
			return
		}
		if !a.checkCSRF(w, r) {
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, user)), user)
	})
}

// writable additionally requires a role that may change things.
func (a *API) writable(h handlerFunc) http.Handler {
	return a.authenticated(func(w http.ResponseWriter, r *http.Request, u model.User) {
		if !auth.CanWrite(u) {
			a.fail(w, http.StatusForbidden, "forbidden", "this account is read-only")
			return
		}
		h(w, r, u)
	})
}

// adminOnly restricts a route to administrators.
func (a *API) adminOnly(h handlerFunc) http.Handler {
	return a.authenticated(func(w http.ResponseWriter, r *http.Request, u model.User) {
		if !auth.IsAdmin(u) {
			a.fail(w, http.StatusForbidden, "forbidden", "administrator access required")
			return
		}
		h(w, r, u)
	})
}

func (a *API) requireSession(w http.ResponseWriter, r *http.Request) (model.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		a.fail(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return model.User{}, false
	}
	user, err := a.Auth.ResolveSession(r.Context(), c.Value)
	if err != nil {
		a.clearCookies(w)
		a.fail(w, http.StatusUnauthorized, "unauthorized", "session expired")
		return model.User{}, false
	}
	return user, true
}

// checkCSRF enforces the double-submit token on state-changing requests.
func (a *API) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		a.fail(w, http.StatusForbidden, "forbidden", "missing CSRF cookie")
		return false
	}
	if sent := r.Header.Get(csrfHeader); sent == "" || sent != c.Value {
		a.fail(w, http.StatusForbidden, "forbidden", "invalid CSRF token")
		return false
	}
	return true
}

// requireMission loads a mission and checks the caller may see it.
func (a *API) requireMission(w http.ResponseWriter, r *http.Request, u model.User) (model.Mission, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Mission{}, false
	}
	return a.missionByID(w, r, u, id)
}

func (a *API) missionByID(w http.ResponseWriter, r *http.Request, u model.User, id int64) (model.Mission, bool) {
	m, err := a.Store.Mission(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "mission")
		return model.Mission{}, false
	}
	allowed, err := a.Auth.CanAccessMission(r.Context(), u, m.ID)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", err.Error())
		return model.Mission{}, false
	}
	if !allowed {
		// Do not confirm the mission exists to someone who may not see it.
		a.fail(w, http.StatusNotFound, "not_found", "mission not found")
		return model.Mission{}, false
	}
	return m, true
}

func (a *API) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 500 {
			a.Log.Error("request failed", "method", r.Method, "path", r.URL.Path,
				"status", rec.status, "duration", time.Since(start))
		} else {
			a.Log.Debug("request", "method", r.Method, "path", r.URL.Path,
				"status", rec.status, "duration", time.Since(start))
		}
	})
}

func (a *API) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				a.Log.Error("panic in handler", "path", r.URL.Path, "panic", p)
				a.fail(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController and the WebSocket hijacker through.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ---------------------------------------------------------------------------
// responses
// ---------------------------------------------------------------------------

type errorBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func (a *API) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg, Code: code})
}

// failStore maps store errors to HTTP statuses.
func (a *API) failStore(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		a.fail(w, http.StatusNotFound, "not_found", what+" not found")
	case errors.Is(err, store.ErrConflict):
		a.fail(w, http.StatusConflict, "conflict", err.Error())
	default:
		a.Log.Error("store error", "what", what, "error", err)
		a.fail(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (a *API) ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if v == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.Log.Warn("cannot encode response", "error", err)
	}
}

func (a *API) created(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body with a size limit.
func (a *API) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		a.fail(w, http.StatusBadRequest, "invalid", "invalid request body: "+err.Error())
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

func (a *API) pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		a.fail(w, http.StatusBadRequest, "invalid", "invalid id")
		return 0, false
	}
	return id, true
}

func queryInt64(r *http.Request, name string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	return v
}

func queryInt(r *http.Request, name string, def int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

// clientIP extracts the remote address, honouring X-Forwarded-For only when
// the server is configured to sit behind a trusted proxy.
func (a *API) clientIP(r *http.Request) string {
	if a.Config.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, ok := strings.Cut(xff, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) audit(r *http.Request, u model.User, missionID int64, action, detail string) {
	a.Store.Audit(r.Context(), u.ID, u.Username, missionID, action, detail, a.clientIP(r))
}

// setCookie writes a cookie with the right security attributes.
func (a *API) setCookie(w http.ResponseWriter, name, value string, expires time.Time, httpOnly bool) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   a.Config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
	if !expires.IsZero() {
		c.MaxAge = int(time.Until(expires).Seconds())
	}
	http.SetCookie(w, c)
}

func (a *API) clearCookies(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie,
			Secure:   a.Config.SecureCookies,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// engineOr reports a clear error when an engine is not available on this
// platform instead of failing with a confusing nil dereference.
func (a *API) engineMissing(w http.ResponseWriter, name string) {
	a.fail(w, http.StatusNotImplemented, "unsupported",
		fmt.Sprintf("%s is not available on this platform or requires raw socket privileges", name))
}

var _ = engine.ErrUnsupported
