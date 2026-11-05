package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// Taking a whole mission off an installation and putting it back on another
// one, which is what happens when the machine it ran on is about to be wiped.

func TestMissionBundleRoundTripOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.newUser("root", model.RoleAdmin)
	admin := e.login("root")
	ctx := t.Context()

	var mission model.Mission
	if got := admin.do("POST", "/api/missions",
		map[string]any{"name": "client A", "client": "ACME"}, &mission); got != http.StatusCreated && got != http.StatusOK {
		t.Fatalf("create mission: %d", got)
	}
	if _, err := e.store.UpsertHost(ctx, model.Host{
		MissionID: mission.ID, NetworkID: 0, IP: "10.9.0.4", Hostname: "srv",
	}); err != nil {
		t.Fatal(err)
	}

	status, body, hdr := admin.raw("GET", "/api/missions/"+itoa(mission.ID)+"/bundle")
	if status != http.StatusOK {
		t.Fatalf("export: %d: %s", status, body)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("content type: %q", ct)
	}
	if cd := hdr.Get("Content-Disposition"); !bytes.Contains([]byte(cd), []byte("client-A")) {
		t.Fatalf("the download should be named after the mission: %q", cd)
	}

	// It really is gzip, and it really is a bundle.
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the download is not gzip: %v", err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	var bundle store.MissionBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("the download is not a bundle: %v", err)
	}
	if bundle.MissionName != "client A" || bundle.Checksum == "" {
		t.Fatalf("bundle: %+v", bundle.MissionName)
	}

	// Back in, as a form upload, which is what a browser sends.
	status, resp := admin.postFile("/api/missions/import?create_users=true&name=client+A+(restored)",
		"client-a.bundle.json.gz", body)
	if status != http.StatusOK {
		t.Fatalf("import: %d: %s", status, resp)
	}
	var res store.ImportResult
	if err := json.Unmarshal(resp, &res); err != nil {
		t.Fatal(err)
	}
	if res.MissionID == mission.ID {
		t.Fatal("an import makes a new mission, it never writes over the one that is there")
	}
	if res.Name != "client A (restored)" {
		t.Fatalf("the name override was ignored: %q", res.Name)
	}
	hosts, err := e.store.ListHosts(ctx, res.MissionID, 0)
	if err != nil || len(hosts) != 1 || hosts[0].IP != "10.9.0.4" {
		t.Fatalf("the host did not come back: %+v, %v", hosts, err)
	}
}

// An uncompressed bundle is accepted too, because someone will unzip the file
// before uploading it.
func TestImportAcceptsAnUncompressedBundle(t *testing.T) {
	e := newEnv(t)
	e.newUser("root", model.RoleAdmin)
	admin := e.login("root")

	var mission model.Mission
	admin.do("POST", "/api/missions", map[string]any{"name": "plain"}, &mission)
	bundle, err := e.store.ExportMission(t.Context(), mission.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	status, resp := admin.postFile("/api/missions/import", "plain.json", raw)
	if status != http.StatusOK {
		t.Fatalf("import: %d: %s", status, resp)
	}
}

// Anything that is not a bundle comes back as a bad request with a reason,
// not as a server error.
func TestImportRejectsRubbish(t *testing.T) {
	e := newEnv(t)
	e.newUser("root", model.RoleAdmin)
	admin := e.login("root")

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"not json", []byte("this is not a bundle at all")},
		{"empty", nil},
		{"json but not a bundle", []byte(`{"hello":"world"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := admin.postFile("/api/missions/import", "x.json", tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("got %d: %s", status, resp)
			}
		})
	}
}

// Importing creates a mission and can recreate accounts, so it belongs to an
// administrator. Exporting is the same privilege as exporting the results,
// which a member already has.
func TestBundlePermissions(t *testing.T) {
	e := newEnv(t)
	e.newUser("root", model.RoleAdmin)
	admin := e.login("root")
	e.newUser("bob", model.RoleOperator)
	bob := e.login("bob")

	var mission model.Mission
	admin.do("POST", "/api/missions", map[string]any{"name": "scoped"}, &mission)

	path := "/api/missions/" + itoa(mission.ID) + "/bundle"
	if status, _, _ := bob.raw("GET", path); status != http.StatusNotFound && status != http.StatusForbidden {
		t.Fatalf("a non member must not be able to take a mission away: %d", status)
	}
	if err := e.store.SetMissionMembers(t.Context(), mission.ID, []int64{bob.user.ID}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := bob.raw("GET", path); status != http.StatusOK {
		t.Fatalf("a member must be able to export their own mission: %d", status)
	}

	if status, _ := bob.postFile("/api/missions/import", "x.json", []byte(`{}`)); status != http.StatusForbidden {
		t.Fatalf("importing is an administrator's: %d", status)
	}
}

// postFile uploads a file the way a browser form does.
func (c *client) postFile(path, filename string, content []byte) (int, []byte) {
	c.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		c.t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		c.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", c.base+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}
