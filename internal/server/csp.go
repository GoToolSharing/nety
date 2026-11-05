package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"regexp"
	"strings"
)

// The SPA's index.html carries one small inline script: it reads the stored theme
// preference and sets it on <html> before the first paint, so the page does not flash the
// wrong colours. Serving it under `script-src 'self'` silently kills it, and loosening
// the policy to 'unsafe-inline' to keep it would give up most of what the CSP is for.
//
// So we hash whatever inline scripts the built index.html actually contains and allow
// exactly those. It is computed once at startup from the embedded file, so it keeps
// working when the SPA changes without anyone remembering to update a constant.

var inlineScriptRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)

// inlineScriptHashes returns the CSP source expressions for every inline script in
// index.html, e.g. `'sha256-…'`.
func inlineScriptHashes(root fs.FS) []string {
	data, err := fs.ReadFile(root, "index.html")
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range inlineScriptRE.FindAllStringSubmatch(string(data), -1) {
		attrs, body := m[1], m[2]
		// A script with a src is not inline; its content is ignored by the browser and
		// must not be hashed.
		if strings.Contains(strings.ToLower(attrs), "src=") {
			continue
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		sum := sha256.Sum256([]byte(body))
		expr := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if seen[expr] {
			continue
		}
		seen[expr] = true
		out = append(out, expr)
	}
	return out
}
