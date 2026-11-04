package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vaadata/nety/internal/config"
)

func TestInlineScriptHashes(t *testing.T) {
	body := "\n      document.documentElement.dataset.theme = 'dark';\n    "
	index := `<!doctype html><html><head>
    <script>` + body + `</script>
    <script type="module" crossorigin src="./assets/index-abc.js"></script>
    <script src="./other.js"></script>
    <script>   </script>
    </head><body></body></html>`

	root := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(index)}}
	got := inlineScriptHashes(root)

	sum := sha256.Sum256([]byte(body))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want exactly [%s]", got, want)
	}
}

func TestInlineScriptHashesHandlesMissingIndex(t *testing.T) {
	if got := inlineScriptHashes(fstest.MapFS{}); got != nil {
		t.Fatalf("expected no hashes when index.html is absent, got %v", got)
	}
}

// TestCSPAllowsTheRealIndexScripts is the regression test for a live bug: the
// policy was blocking the SPA's theme bootstrap, which runs inline before the
// first paint. Any inline script the built index.html carries must be covered.
func TestCSPAllowsTheRealIndexScripts(t *testing.T) {
	root, err := webRoot()
	if err != nil {
		t.Fatalf("web root: %v", err)
	}
	data, err := fs.ReadFile(root, "index.html")
	if err != nil {
		t.Skip("no built index.html to check")
	}

	hashes := inlineScriptHashes(root)
	h := securityHeaders(config.Config{}, hashes, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no CSP header")
	}
	if strings.Contains(directive(csp, "script-src"), "'unsafe-inline'") {
		t.Fatalf("the policy must not fall back to 'unsafe-inline' for scripts: %s", csp)
	}
	for _, m := range inlineScriptRE.FindAllStringSubmatch(string(data), -1) {
		if strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) == "" {
			continue
		}
		sum := sha256.Sum256([]byte(m[2]))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(csp, want) {
			t.Fatalf("index.html has an inline script the CSP does not allow (%s)\npolicy: %s", want, csp)
		}
	}
}

// directive returns one directive of a CSP header, e.g. "script-src 'self' …".
func directive(csp, name string) string {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+" ") || part == name {
			return part
		}
	}
	return ""
}

func TestSecurityHeadersAreSet(t *testing.T) {
	h := securityHeaders(config.Config{}, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	for header, want := range map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "no-referrer",
		"Strict-Transport-Security":  "max-age=31536000",
		"Cross-Origin-Opener-Policy": "same-origin",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}

	// With TLS disabled HSTS makes no sense and must not be sent.
	h = securityHeaders(config.Config{TLSDisabled: true}, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS must not be sent over plain HTTP, got %q", got)
	}
}

func TestSPAFallsBackToIndex(t *testing.T) {
	root := fstest.MapFS{
		"index.html":        &fstest.MapFile{Data: []byte("<!doctype html><title>app</title>")},
		"assets/app-abc.js": &fstest.MapFile{Data: []byte("console.log(1)")},
	}
	h := spaHandler(root)

	// A client-side route must get the app shell, not a 404.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/missions/12/matrix", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>app</title>") {
		t.Fatalf("client route should serve index.html, got %d %q", rec.Code, rec.Body.String())
	}

	// Hashed assets are cached hard, the shell is not.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/app-abc.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("asset: %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("hashed assets should be immutable, got %q", cc)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("the shell must not be cached, got %q", cc)
	}
}
