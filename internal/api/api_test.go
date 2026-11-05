package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/auth"
	"github.com/GoToolSharing/nety/internal/bus"
	"github.com/GoToolSharing/nety/internal/config"
	"github.com/GoToolSharing/nety/internal/export"
	"github.com/GoToolSharing/nety/internal/jobs"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

const testPassword = "correct-horse-9A"

type testEnv struct {
	t      *testing.T
	srv    *httptest.Server
	store  *store.Store
	auth   *auth.Service
	runner *jobs.Runner
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), nil)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Default()
	cfg.TLSDisabled = true // httptest serves plain HTTP
	cfg.SecureCookies = false
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.SecureCookies = false

	authSvc := auth.New(st, auth.Config{SessionTTL: time.Hour, SessionIdleTTL: time.Hour, MaxAttempts: 50})
	b := bus.New()
	t.Cleanup(b.Close)
	runner := jobs.New(st, b, jobs.Engines{}, jobs.Options{}, nil)
	t.Cleanup(runner.Close)

	api := New(Deps{
		Store: st, Auth: authSvc, Bus: b, Runner: runner,
		Exporter: export.New(), Config: cfg,
	})
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	return &testEnv{t: t, srv: srv, store: st, auth: authSvc, runner: runner}
}

// client is a logged-in HTTP client that carries cookies and the CSRF token.
type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
	user model.User
}

func (e *testEnv) newUser(username string, role model.Role) model.User {
	e.t.Helper()
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.store.CreateUser(context.Background(), model.User{
		Username: username, Role: role, PasswordHash: hash,
	})
	if err != nil {
		e.t.Fatalf("create user: %v", err)
	}
	return u
}

func (e *testEnv) anonymous() *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, base: e.srv.URL, http: &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (e *testEnv) login(username string) *client {
	e.t.Helper()
	c := e.anonymous()
	var resp sessionResponse
	status := c.do("POST", "/api/auth/login", map[string]string{
		"username": username, "password": testPassword,
	}, &resp)
	if status != http.StatusOK {
		e.t.Fatalf("login as %s failed with %d", username, status)
	}
	c.csrf = resp.CSRFToken
	c.user = resp.User
	return c
}

// do performs a request and decodes the body into out (which may be nil).
func (c *client) do(method, path string, body, out any) int {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			c.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode
}

// rawPost sends a body and returns the status and the raw response, for the cases where
// the error text itself is what is being asserted.
func (c *client) rawPost(path string, body any) (int, []byte, http.Header) {
	c.t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		c.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, resp.Header
}

// raw performs a request without decoding, returning status and body.
func (c *client) raw(method, path string) (int, []byte, http.Header) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, nil)
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, resp.Header
}

func (c *client) createMission(name string) model.Mission {
	c.t.Helper()
	var m model.Mission
	if st := c.do("POST", "/api/missions", map[string]any{"name": name}, &m); st != http.StatusCreated {
		c.t.Fatalf("create mission: status %d", st)
	}
	return m
}

func (c *client) createNetwork(missionID int64, name string) model.Network {
	c.t.Helper()
	var n model.Network
	st := c.do("POST", "/api/missions/"+itoa(missionID)+"/networks", map[string]any{
		"name": name, "vlan_id": 10, "prefixes": []string{"10.0.0.0/24"},
	}, &n)
	if st != http.StatusCreated {
		c.t.Fatalf("create network: status %d", st)
	}
	return n
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// --------------------------------------------------------------------------- tests
// ---------------------------------------------------------------------------

func TestAnonymousAccessIsRefused(t *testing.T) {
	e := newEnv(t)
	c := e.anonymous()

	// The version is public so a load balancer can probe it...
	var status map[string]any
	if got := c.do("GET", "/api/status", nil, &status); got != http.StatusOK {
		t.Fatalf("status should be public, got %d", got)
	}
	if _, leaked := status["database"]; leaked {
		t.Fatal("anonymous status must not expose database counters")
	}
	// ...everything else is not.
	for _, path := range []string{"/api/missions", "/api/users", "/api/auth/me", "/api/interfaces"} {
		if got := c.do("GET", path, nil, nil); got != http.StatusUnauthorized {
			t.Fatalf("%s should require a session, got %d", path, got)
		}
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	c := e.anonymous()

	if got := c.do("POST", "/api/auth/login", map[string]string{
		"username": "alice", "password": "wrong",
	}, nil); got != http.StatusUnauthorized {
		t.Fatalf("a wrong password must be refused, got %d", got)
	}

	alice := e.login("alice")
	if alice.user.Username != "alice" || alice.csrf == "" {
		t.Fatalf("unexpected session %+v", alice.user)
	}
	if alice.user.PasswordHash != "" {
		t.Fatal("the password hash must never be serialised")
	}

	var me sessionResponse
	if got := alice.do("GET", "/api/auth/me", nil, &me); got != http.StatusOK || me.User.ID != alice.user.ID {
		t.Fatalf("me: status %d user %+v", got, me.User)
	}
	if got := alice.do("POST", "/api/auth/logout", nil, nil); got != http.StatusOK {
		t.Fatalf("logout: %d", got)
	}
	if got := alice.do("GET", "/api/auth/me", nil, nil); got != http.StatusUnauthorized {
		t.Fatalf("the session must be gone after logout, got %d", got)
	}
}

func TestCSRFIsEnforced(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")

	good := alice.csrf
	alice.csrf = "" // no header at all
	if got := alice.do("POST", "/api/missions", map[string]any{"name": "x"}, nil); got != http.StatusForbidden {
		t.Fatalf("a missing CSRF header must be refused, got %d", got)
	}
	alice.csrf = "not-the-right-token"
	if got := alice.do("POST", "/api/missions", map[string]any{"name": "x"}, nil); got != http.StatusForbidden {
		t.Fatalf("a wrong CSRF token must be refused, got %d", got)
	}
	alice.csrf = good
	if got := alice.do("POST", "/api/missions", map[string]any{"name": "x"}, nil); got != http.StatusCreated {
		t.Fatalf("the correct token must be accepted, got %d", got)
	}
	// Reads never need the token.
	alice.csrf = ""
	if got := alice.do("GET", "/api/missions", nil, nil); got != http.StatusOK {
		t.Fatalf("GET must not require CSRF, got %d", got)
	}
}

// TestMissionIsolation is the one that matters on a shared engagement box:
// a user must not see another team's mission, and must not be able to tell whether it
// exists.
func TestMissionIsolation(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	e.newUser("bob", model.RoleOperator)
	e.newUser("root", model.RoleAdmin)

	alice := e.login("alice")
	bob := e.login("bob")
	admin := e.login("root")

	m := alice.createMission("ACME")

	var mine []model.Mission
	alice.do("GET", "/api/missions", nil, &mine)
	if len(mine) != 1 || mine[0].ID != m.ID {
		t.Fatalf("the creator should see their mission, got %+v", mine)
	}

	var bobsList []model.Mission
	bob.do("GET", "/api/missions", nil, &bobsList)
	if len(bobsList) != 0 {
		t.Fatalf("bob must not see alice's mission, got %+v", bobsList)
	}
	// 404, not 403: do not confirm the mission exists.
	if got := bob.do("GET", "/api/missions/"+itoa(m.ID), nil, nil); got != http.StatusNotFound {
		t.Fatalf("expected 404 for a foreign mission, got %d", got)
	}
	for _, path := range []string{"/hosts", "/services", "/findings", "/assets", "/matrix", "/scans"} {
		if got := bob.do("GET", "/api/missions/"+itoa(m.ID)+path, nil, nil); got != http.StatusNotFound {
			t.Fatalf("%s leaked to a non-member (status %d)", path, got)
		}
	}

	// An admin sees everything.
	var all []model.Mission
	admin.do("GET", "/api/missions", nil, &all)
	if len(all) != 1 {
		t.Fatalf("an admin should see every mission, got %+v", all)
	}

	// Once bob is a member, he can read it.
	if got := admin.do("PUT", "/api/missions/"+itoa(m.ID)+"/members",
		map[string]any{"user_ids": []int64{alice.user.ID, bob.user.ID}}, nil); got != http.StatusOK {
		t.Fatalf("set members: %d", got)
	}
	if got := bob.do("GET", "/api/missions/"+itoa(m.ID), nil, nil); got != http.StatusOK {
		t.Fatalf("a member must be able to read the mission, got %d", got)
	}
}

func TestViewerCannotWrite(t *testing.T) {
	e := newEnv(t)
	e.newUser("vicky", model.RoleViewer)
	e.newUser("root", model.RoleAdmin)
	admin := e.login("root")
	m := admin.createMission("ACME")
	admin.do("PUT", "/api/missions/"+itoa(m.ID)+"/members",
		map[string]any{"user_ids": []int64{admin.user.ID, 1}}, nil)

	vicky := e.login("vicky")
	if got := vicky.do("POST", "/api/missions", map[string]any{"name": "nope"}, nil); got != http.StatusForbidden {
		t.Fatalf("a viewer must not create missions, got %d", got)
	}
	if got := vicky.do("GET", "/api/missions", nil, nil); got != http.StatusOK {
		t.Fatalf("a viewer must still be able to read, got %d", got)
	}
}

func TestOnlyAdminsManageUsers(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	e.newUser("root", model.RoleAdmin)
	alice := e.login("alice")
	admin := e.login("root")

	if got := alice.do("GET", "/api/users", nil, nil); got != http.StatusForbidden {
		t.Fatalf("an operator must not list users, got %d", got)
	}
	var created struct {
		model.User
		GeneratedPassword string `json:"generated_password"`
	}
	if got := admin.do("POST", "/api/users", map[string]any{
		"username": "carol", "role": "viewer",
	}, &created); got != http.StatusCreated {
		t.Fatalf("create user: %d", got)
	}
	if created.GeneratedPassword == "" {
		t.Fatal("a generated password should be returned once")
	}
	if !created.MustChangePW {
		t.Fatal("a new account must be flagged for a password change")
	}
	// An admin cannot lock themselves out.
	if got := admin.do("DELETE", "/api/users/"+itoa(admin.user.ID), nil, nil); got != http.StatusBadRequest {
		t.Fatalf("deleting your own account must be refused, got %d", got)
	}
	if got := admin.do("PATCH", "/api/users/"+itoa(admin.user.ID),
		map[string]any{"role": "viewer"}, nil); got != http.StatusBadRequest {
		t.Fatalf("demoting yourself must be refused, got %d", got)
	}
}

func TestScanValidationRejectsBadOptions(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	cases := []struct {
		name string
		opts map[string]any
	}{
		{"bad ports", map[string]any{"tcp_ports": "not-a-port", "targets": []string{"10.0.0.0/24"}}},
		{"bad targets", map[string]any{"tcp_ports": "80", "targets": []string{"999.999.0.0/24"}}},
		{"no targets", map[string]any{"tcp_ports": "80", "auto_targets": false}},
		{"rate over the cap", map[string]any{"tcp_ports": "80", "targets": []string{"10.0.0.0/24"}, "rate": 99999999}},
		{"bad mode", map[string]any{"tcp_ports": "80", "targets": []string{"10.0.0.0/24"}, "scan_mode": "magic"}},
	}
	for _, tc := range cases {
		got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/scans", map[string]any{
			"network_id": n.ID, "kind": "discovery", "options": tc.opts,
		}, nil)
		if got != http.StatusBadRequest {
			t.Fatalf("%s should be refused, got %d", tc.name, got)
		}
	}

	// A scan on a network of another mission is refused.
	other := alice.createMission("OTHER")
	if got := alice.do("POST", "/api/missions/"+itoa(other.ID)+"/scans", map[string]any{
		"network_id": n.ID, "kind": "discovery",
		"options": map[string]any{"tcp_ports": "80", "targets": []string{"10.0.0.0/24"}},
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("a network from another mission must be refused, got %d", got)
	}
}

func TestScanLifecycleEndpoints(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	var sc model.Scan
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/scans", map[string]any{
		"network_id": n.ID, "kind": "discovery",
		"options": map[string]any{"tcp_ports": "80", "targets": []string{"10.0.0.0/30"}},
	}, &sc); got != http.StatusCreated {
		t.Fatalf("create scan: %d", got)
	}
	if sc.Status != model.ScanQueued {
		t.Fatalf("a new scan should be queued, got %q", sc.Status)
	}

	// Pausing or stopping something that is not running is a clear conflict, not a silent
	// success.
	for _, action := range []string{"pause", "stop"} {
		if got := alice.do("POST", "/api/scans/"+itoa(sc.ID)+"/"+action, nil, nil); got != http.StatusConflict {
			t.Fatalf("%s on an idle scan should be a conflict, got %d", action, got)
		}
	}

	// With no engines wired the scan completes immediately, which is enough to exercise
	// the endpoint and the audit trail.
	if got := alice.do("POST", "/api/scans/"+itoa(sc.ID)+"/start", nil, nil); got != http.StatusOK {
		t.Fatalf("start: %d", got)
	}
	deadline := time.Now().Add(10 * time.Second)
	var final model.Scan
	for time.Now().Before(deadline) {
		alice.do("GET", "/api/scans/"+itoa(sc.ID), nil, &final)
		if final.Status == model.ScanCompleted || final.Status == model.ScanFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final.Status != model.ScanCompleted {
		t.Fatalf("expected the scan to complete, got %q (%s)", final.Status, final.Error)
	}

	var logs []store.ScanLog
	if got := alice.do("GET", "/api/scans/"+itoa(sc.ID)+"/logs", nil, &logs); got != http.StatusOK {
		t.Fatalf("logs: %d", got)
	}
	if len(logs) == 0 {
		t.Fatal("a scan should leave a log trail")
	}
}

func TestExportEndpoint(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME & Co")
	alice.createNetwork(m.ID, "VLAN10")

	for _, format := range []string{"json", "csv-services", "nmap-xml", "markdown", "html", "xlsx"} {
		status, body, header := alice.raw("GET", "/api/missions/"+itoa(m.ID)+"/export?format="+format)
		if status != http.StatusOK {
			t.Fatalf("export %s: status %d", format, status)
		}
		if len(body) == 0 {
			t.Fatalf("export %s returned an empty body", format)
		}
		cd := header.Get("Content-Disposition")
		if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "nety-acme-co-") {
			t.Fatalf("export %s: unexpected Content-Disposition %q", format, cd)
		}
	}
	if status, _, _ := alice.raw("GET", "/api/missions/"+itoa(m.ID)+"/export?format=nope"); status != http.StatusBadRequest {
		t.Fatalf("an unknown format must be refused, got %d", status)
	}
}

func TestCatalogEndpoints(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")

	var profiles []scanProfile
	if got := alice.do("GET", "/api/scan-profiles", nil, &profiles); got != http.StatusOK || len(profiles) < 3 {
		t.Fatalf("profiles: status %d, %d entries", got, len(profiles))
	}
	for _, p := range profiles {
		if p.Options.TCPPorts == "" || p.Description == "" {
			t.Fatalf("profile %s is incomplete: %+v", p.ID, p)
		}
	}
	var formats []map[string]any
	if got := alice.do("GET", "/api/export-formats", nil, &formats); got != http.StatusOK || len(formats) == 0 {
		t.Fatalf("formats: status %d, %d entries", got, len(formats))
	}
}

func TestEngineMissingIsReportedClearly(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")

	// The env wires no engines, so interface listing must say so rather than panicking on
	// a nil interface.
	status, body, _ := alice.raw("GET", "/api/interfaces")
	if status != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", status)
	}
	if !strings.Contains(string(body), "not available") {
		t.Fatalf("unhelpful error body: %s", body)
	}
}

func TestInvalidBodyIsRejected(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")

	req, _ := http.NewRequest("POST", alice.base+"/api/missions", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, alice.csrf)
	resp, err := alice.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON must be refused, got %d", resp.StatusCode)
	}
	// Unknown fields are refused too, so a typo in a client is not silent.
	if got := alice.do("POST", "/api/missions", map[string]any{
		"name": "x", "nmae": "typo",
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("unknown fields must be refused, got %d", got)
	}
}

// TestPasswordChangeIsEnforcedServerSide checks that an account flagged for a password
// change really cannot do anything else: the flag is a security control, not a hint for
// the client.
func TestPasswordChangeIsEnforcedServerSide(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("newcomer", model.RoleOperator)
	u.MustChangePW = true
	if err := e.store.UpdateUser(context.Background(), u); err != nil {
		t.Fatalf("flag user: %v", err)
	}

	c := e.login("newcomer")
	if !c.user.MustChangePW {
		t.Fatal("the session should report that a password change is due")
	}
	for _, path := range []string{"/api/missions", "/api/scan-profiles"} {
		status, body, _ := c.raw("GET", path)
		if status != http.StatusForbidden {
			t.Fatalf("%s should be blocked, got %d", path, status)
		}
		if !strings.Contains(string(body), "password_change_required") {
			t.Fatalf("%s: the client needs a machine-readable code, got %s", path, body)
		}
	}
	// The way out stays open.
	if got := c.do("GET", "/api/auth/me", nil, nil); got != http.StatusOK {
		t.Fatalf("/api/auth/me must stay reachable, got %d", got)
	}
	if got := c.do("POST", "/api/auth/password", map[string]string{
		"current_password": testPassword, "new_password": "brand-new-pass-7B",
	}, nil); got != http.StatusOK {
		t.Fatalf("changing the password must be allowed, got %d", got)
	}

	// After the change the account works normally.
	c2 := e.anonymous()
	var resp sessionResponse
	if got := c2.do("POST", "/api/auth/login", map[string]string{
		"username": "newcomer", "password": "brand-new-pass-7B",
	}, &resp); got != http.StatusOK {
		t.Fatalf("login with the new password: %d", got)
	}
	c2.csrf = resp.CSRFToken
	if resp.User.MustChangePW {
		t.Fatal("the flag should be cleared after the change")
	}
	if got := c2.do("GET", "/api/missions", nil, nil); got != http.StatusOK {
		t.Fatalf("the account should work normally now, got %d", got)
	}
}

// The export is a deliverable by default: the rows the operator decided against stay out
// of it, and so do the findings nobody has read. The file says how many it held back, and
// either switch brings its own back.
func TestExportLeavesOutWhatWasSetAside(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME & Co")
	n := alice.createNetwork(m.ID, "VLAN10")
	ctx := t.Context()

	host, err := e.store.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: n.ID, IP: "10.1.2.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A service nobody triaged. It must survive every combination: the list of open ports
	// is inventory, not a claim.
	if _, err := e.store.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: n.ID, HostID: host.ID, IP: host.IP,
		Port: 445, Protocol: model.TCP, Name: "microsoft-ds",
	}); err != nil {
		t.Fatal(err)
	}

	newFinding := func(check, title string, sev model.Severity) model.Finding {
		f, err := e.store.UpsertFinding(ctx, model.Finding{
			MissionID: m.ID, NetworkID: n.ID, HostID: host.ID, IP: host.IP,
			CheckID: check, Title: title, Severity: sev,
		})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	keep := newFinding("smb.signing", "SMB signing not required", model.SevMedium)
	falsePositive := newFinding("tls.weak", "Weak TLS cipher", model.SevLow)
	unread := newFinding("http.banner", "Server banner", model.SevInfo)

	flagged := model.TriageFlagged
	if _, err := e.store.SetFindingTriage(ctx, keep.ID, &flagged, nil, alice.user.ID); err != nil {
		t.Fatal(err)
	}
	fp := model.TriageFalsePositive
	if _, err := e.store.SetFindingTriage(ctx, falsePositive.ID, &fp, nil, alice.user.ID); err != nil {
		t.Fatal(err)
	}

	get := func(query string) model.MissionData {
		t.Helper()
		var d model.MissionData
		if st := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/export?format=json"+query,
			nil, &d); st != http.StatusOK {
			t.Fatalf("export%s: %d", query, st)
		}
		return d
	}

	deliverable := get("")
	if len(deliverable.Findings) != 1 || deliverable.Findings[0].ID != keep.ID {
		t.Fatalf("only the reviewed finding belongs in the deliverable: %+v",
			deliverable.Findings)
	}
	if len(deliverable.Services) != 1 {
		t.Fatalf("a service is never held back for being unreviewed: %+v",
			deliverable.Services)
	}
	if deliverable.Omitted.SetAside.Findings != 1 {
		t.Fatalf("set aside: got %d, want 1", deliverable.Omitted.SetAside.Findings)
	}
	if deliverable.Omitted.Unreviewed.Findings != 1 {
		t.Fatalf("unreviewed: got %d, want 1", deliverable.Omitted.Unreviewed.Findings)
	}

	// Each switch brings back its own, and only its own.
	withUnread := get("&include_unreviewed=1")
	if len(withUnread.Findings) != 2 {
		t.Fatalf("the unread finding should be back, the false positive not: %+v",
			withUnread.Findings)
	}
	for _, f := range withUnread.Findings {
		if f.ID == falsePositive.ID {
			t.Fatal("include_unreviewed must not bring back what was set aside")
		}
	}

	withSetAside := get("&include_dismissed=1")
	for _, f := range withSetAside.Findings {
		if f.ID == unread.ID {
			t.Fatal("include_dismissed must not bring back what nobody has read")
		}
	}

	whole := get("&include_dismissed=1&include_unreviewed=1")
	if len(whole.Findings) != 3 {
		t.Fatalf("the whole record must carry all three: %+v", whole.Findings)
	}
	if whole.Omitted.Any() {
		t.Fatalf("nothing was held back, so nothing should be claimed: %+v", whole.Omitted)
	}

	// And a report says it on its own front page, not only in the JSON.
	status, body, _ := alice.raw("GET", "/api/missions/"+itoa(m.ID)+"/export?format=markdown")
	if status != http.StatusOK {
		t.Fatalf("markdown export: %d", status)
	}
	if !strings.Contains(string(body), "left out of this export") {
		t.Fatal("a report that is shorter than the mission has to say so on its own")
	}
	if !strings.Contains(string(body), "nobody had reviewed yet") {
		t.Fatal("and has to say which of the two reasons applied")
	}
}
