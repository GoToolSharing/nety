package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("http-vcs-exposed", "Version control or environment file served by the web server", model.SevHigh,
			[]string{"http", "https"},
			"The web server serves files that belong to the deployment rather than to the site. A readable .git directory reconstructs the whole repository, which is the application's source code and, far more often than anyone expects, the credentials that were committed and later removed from the working tree but never from the history. A readable .env is the running configuration itself: database password, application key, mail and cloud credentials, in one file. Both come from deploying with a copy or a checkout rather than a build, and neither leaves a trace in the application's own logs when it is read."),
		Remediation: "Deploy from a build artefact rather than a working copy, and have the web server refuse the metadata directories outright (a location block on .git, .svn, .hg and .env that returns 404). Treat every secret that was in a reachable .env or in the repository history as compromised and rotate it.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
			"https://cwe.mitre.org/data/definitions/538.html",
		},
		Applies: func(t *Target) bool {
			return webIsHTTP(t.Service)
		},
		Run: runHTTPVCSExposed,
	})
}

// vcsArtifact is one file worth asking for, with a test that proves the
// response really is that file. Status codes are never enough on their own:
// a single page application answers 200 with its shell for every path, and a WAF answers
// 403 for paths that are not there at all.
type vcsArtifact struct {
	path     string
	what     string
	severity model.Severity
	confirm  func(body []byte, contentType string) (string, bool)
}

var (
	gitHeadRe   = regexp.MustCompile(`^(ref: refs/[A-Za-z0-9._/-]+|[0-9a-f]{40})\s*$`)
	gitRemoteRe = regexp.MustCompile(`(?m)^\s*url\s*=\s*(\S+)`)
)

// envKeyRe matches a shell style assignment of an upper case key, which is what a dotenv
// file is made of.
var envKeyRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}\s*=`)

// envSecretKeys are the keys that make a dotenv file a credential file. One of them has
// to be present before anything is reported, so a stray text file full of assignments
// does not become a finding.
var envSecretKeys = []string{
	"APP_KEY", "APP_SECRET", "SECRET_KEY", "DB_PASSWORD", "DATABASE_URL",
	"MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD",
	"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "MAIL_PASSWORD",
	"JWT_SECRET", "API_KEY", "API_SECRET", "DB_CONNECTION", "APP_ENV",
}

var vcsArtifacts = []vcsArtifact{
	{
		path: "/.git/HEAD", what: "git repository metadata", severity: model.SevHigh,
		confirm: func(body []byte, _ string) (string, bool) {
			line := strings.TrimSpace(string(bytes.SplitN(body, []byte("\n"), 2)[0]))
			if len(body) > 256 || !gitHeadRe.MatchString(line) {
				return "", false
			}
			return "body is a valid git HEAD: " + line, true
		},
	},
	{
		path: "/.git/config", what: "git repository configuration", severity: model.SevHigh,
		confirm: func(body []byte, _ string) (string, bool) {
			if !bytes.Contains(body, []byte("[core]")) || !bytes.Contains(body, []byte("repositoryformatversion")) {
				return "", false
			}
			// The remote URL names the internal git server, and sometimes carries a
			// token. Only the host part is worth quoting.
			if m := gitRemoteRe.FindSubmatch(body); m != nil {
				return "git config with remote " + printable(m[1], 120), true
			}
			return "git config with [core] repositoryformatversion", true
		},
	},
	{
		path: "/.svn/entries", what: "subversion working copy metadata", severity: model.SevMedium,
		confirm: func(body []byte, _ string) (string, bool) {
			head := strings.TrimSpace(string(bytes.SplitN(body, []byte("\n"), 2)[0]))
			switch {
			case bytes.Contains(body, []byte("svn-entries")) || bytes.Contains(body, []byte("wc-entries")):
				return "svn entries XML", true
			case head != "" && strings.IndexFunc(head, func(r rune) bool { return r < '0' || r > '9' }) == -1 && bytes.Contains(body, []byte("dir")):
				return "svn entries format version " + head, true
			}
			return "", false
		},
	},
	{
		path: "/.env", what: "application environment file", severity: model.SevHigh,
		confirm: func(body []byte, contentType string) (string, bool) {
			// A site that answers every path with its HTML shell would match nothing
			// below, but rule HTML out explicitly all the same.
			if strings.Contains(strings.ToLower(contentType), "html") || bytes.Contains(body, []byte("<html")) {
				return "", false
			}
			if !envKeyRe.Match(body) {
				return "", false
			}
			var found []string
			for _, line := range bytes.Split(body, []byte("\n")) {
				raw, _, ok := bytes.Cut(bytes.TrimSpace(line), []byte("="))
				if !ok {
					continue
				}
				name := strings.ToUpper(strings.TrimSpace(string(raw)))
				for _, want := range envSecretKeys {
					if name == want && !ldapContainsFold(found, want) {
						found = append(found, want)
					}
				}
			}
			if len(found) == 0 {
				return "", false
			}
			// The key names are the evidence. The values are secrets and are deliberately
			// not copied into the finding.
			return fmt.Sprintf("dotenv file with %d assignments, including %s (values not recorded)",
				len(envKeyRe.FindAll(body, -1)), strings.Join(limitStrings(found, 8), ", ")), true
		},
	},
	{
		path: "/.DS_Store", what: "macOS directory index", severity: model.SevLow,
		confirm: func(body []byte, _ string) (string, bool) {
			// The format starts with a 4 byte alignment word then "Bud1".
			if len(body) < 8 || !bytes.Equal(body[4:8], []byte("Bud1")) {
				return "", false
			}
			return fmt.Sprintf("Bud1 directory store, %d bytes: it lists the file names of the directory it was uploaded from", len(body)), true
		},
	},
}

func runHTTPVCSExposed(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	schemes := webSchemes(t.Service)
	scheme := schemes[0]
	var (
		lines []string
		sev   = model.SevInfo
	)
	for i, a := range vcsArtifacts {
		if ctx.Err() != nil {
			break
		}
		var (
			r   *webResp
			err error
		)
		if i == 0 {
			// The first request also settles which scheme answers. Keep the fallback
			// scheme when it fails, so a single refused request does not leave the rest
			// of the loop building unusable URLs.
			var sc string
			if r, sc, err = webGetFirst(ctx, t, c, a.path, nil); sc != "" {
				scheme = sc
			}
		} else {
			r, err = webDo(ctx, c, http.MethodGet, webURL(t, scheme, a.path), nil, nil)
		}
		if err != nil || r.Status != http.StatusOK || len(r.Body) == 0 {
			continue
		}
		detail, ok := a.confirm(r.Body, r.Header.Get("Content-Type"))
		if !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("  GET %-16s -> 200  %s (%s)", a.path, detail, a.what))
		if sevRank(a.severity) > sevRank(sev) {
			sev = a.severity
		}
	}
	if len(lines) == 0 {
		return nil
	}
	f := t.Finding(fmt.Sprintf("Files confirmed by their content, not by their status code, on %s://%s:\n%s",
		scheme, t.Addr(), strings.Join(lines, "\n")))
	f.Severity = sev
	if sev != model.SevHigh {
		f.Title = "Deployment metadata served by the web server"
	}
	return []model.Finding{f}
}
