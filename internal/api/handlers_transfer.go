package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/config"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// Moving a whole mission off one installation and back onto another.
//
// The other exports are readings of the results, shaped for a client or for
// another tool. This one is the results themselves: every row of every table
// the mission owns, including the parts nothing else carries, such as the
// pending work units of a paused scan and who wrote which note. It is what you
// take before a machine is wiped.

// maxBundleBytes bounds what an import will read. A bundle is compressed, so
// this is applied to the decompressed stream: without it a small file could
// expand until the process runs out of memory.
const maxBundleBytes = 2 << 30 // 2 GiB

// handleExportBundle streams the mission as a gzipped bundle.
func (a *API) handleExportBundle(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	bundle, err := a.Store.ExportMission(r.Context(), m.ID, config.Version)
	if err != nil {
		a.failStore(w, err, "mission")
		return
	}

	filename := bundleFilename(m.Name)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		"attachment; filename=\""+filename+"\"; filename*=UTF-8''"+url.PathEscape(filename))

	gz := gzip.NewWriter(w)
	gz.Name = strings.TrimSuffix(filename, ".gz")
	if err := json.NewEncoder(gz).Encode(bundle); err != nil {
		// The headers have gone out, so the only honest thing left is to stop
		// writing and say so in the log: a truncated file fails its checksum
		// on the way back in, which is what that checksum is for.
		a.Log.Error("bundle export failed", "mission", m.ID, "error", err)
		return
	}
	if err := gz.Close(); err != nil {
		a.Log.Error("bundle export failed", "mission", m.ID, "error", err)
		return
	}
	a.audit(r, u, m.ID, "mission.bundle.exported", fmt.Sprintf("%d tables", len(bundle.Tables)))
}

// handleImportBundle restores a bundle as a new mission.
//
// It is administrators only: it creates a mission, and with create_users it
// creates accounts. It never merges into an existing mission, so a restore
// cannot quietly reconcile two versions of one engagement.
func (a *API) handleImportBundle(w http.ResponseWriter, r *http.Request, u model.User) {
	body, cleanup, err := bundleReader(r)
	if err != nil {
		a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	defer cleanup()

	var bundle store.MissionBundle
	dec := json.NewDecoder(io.LimitReader(body, maxBundleBytes))
	// Numbers stay exact: an id or a millisecond timestamp read as a float
	// and written back would not be the same value.
	dec.UseNumber()
	if err := dec.Decode(&bundle); err != nil {
		a.fail(w, http.StatusBadRequest, "invalid",
			"this file is not a NETY mission bundle: "+err.Error())
		return
	}

	opts := store.ImportOptions{
		Name:               strings.TrimSpace(r.URL.Query().Get("name")),
		CreateMissingUsers: queryYes(r, "create_users"),
		OwnerID:            u.ID,
	}
	res, err := a.Store.ImportMission(r.Context(), bundle, opts)
	if err != nil {
		// Every failure here is about the file the caller sent, not about the
		// server, so it reads as a bad request with the reason in it.
		a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	a.audit(r, u, res.MissionID, "mission.bundle.imported", fmt.Sprintf(
		"%s: %d hosts, %d services, %d findings, %d users recreated",
		res.Name, res.Counts["hosts"], res.Counts["services"],
		res.Counts["findings"], len(res.UsersCreated)))
	a.ok(w, res)
}

// bundleReader returns the bundle's bytes, from a form upload or from the
// request body, transparently ungzipped.
func bundleReader(r *http.Request) (io.Reader, func(), error) {
	var raw io.Reader = r.Body
	cleanup := func() {}

	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
		// 32 MiB in memory, the rest spooled to a temporary file, which is
		// what a browser upload of a large mission needs.
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, cleanup, fmt.Errorf("could not read the upload: %w", err)
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			return nil, cleanup, fmt.Errorf("attach the bundle as the form field %q", "file")
		}
		raw = f
		cleanup = func() {
			f.Close()
			if r.MultipartForm != nil {
				r.MultipartForm.RemoveAll()
			}
		}
	}

	// Accept the file either compressed or not, because someone will unzip it
	// before uploading it and that should still work.
	buf := make([]byte, 2)
	n, err := io.ReadFull(raw, buf)
	if err != nil && n == 0 {
		cleanup()
		return nil, func() {}, fmt.Errorf("the file is empty")
	}
	head := io.MultiReader(strings.NewReader(string(buf[:n])), raw)
	if n == 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		gz, err := gzip.NewReader(head)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("the file looks compressed but cannot be read: %w", err)
		}
		prev := cleanup
		return gz, func() { gz.Close(); prev() }, nil
	}
	return head, cleanup, nil
}

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// bundleFilename names the download after the mission and the day, so a folder
// of backups is readable without opening any of them.
func bundleFilename(mission string) string {
	slug := strings.Trim(unsafeFilename.ReplaceAllString(mission, "-"), "-")
	if slug == "" {
		slug = "mission"
	}
	if len(slug) > 60 {
		slug = strings.Trim(slug[:60], "-")
	}
	return fmt.Sprintf("nety-%s-%s.bundle.json.gz", slug, time.Now().UTC().Format("2006-01-02"))
}

// queryYes reads a boolean query parameter. Anything but a clear yes is no.
func queryYes(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
