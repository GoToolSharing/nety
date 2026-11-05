package checks

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// webMaxBody bounds every HTTP body read by checks.
const webMaxBody = 256 << 10

// webResp is a fully read (and bounded) HTTP response.
type webResp struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string
}

// webIsHTTP reports whether s looks like an HTTP(S) service.
func webIsHTTP(s model.Service) bool {
	if s.Protocol != model.TCP {
		return false
	}
	if s.HTTP != nil {
		return true
	}
	n := strings.ToLower(s.Name)
	return strings.Contains(n, "http") || n == "ssl/http" || n == "https"
}

// webSchemes returns the schemes worth trying for s, most likely first.
func webSchemes(s model.Service) []string {
	if s.HTTP != nil && (s.HTTP.Scheme == "http" || s.HTTP.Scheme == "https") {
		return []string{s.HTTP.Scheme}
	}
	if isTLS(s) || strings.Contains(strings.ToLower(s.Name), "https") {
		return []string{"https"}
	}
	return []string{"http", "https"}
}

// webHeader returns a header captured by the fingerprinter (case-insensitive).
func webHeader(s model.Service, key string) string {
	if s.HTTP == nil {
		return ""
	}
	for k, v := range s.HTTP.Headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// webFingerprintText concatenates the fingerprint facts used to recognise products
// (title, server, technologies, product, banner), lowercased.
func webFingerprintText(s model.Service) string {
	parts := []string{s.Product, s.Name, s.ExtraInfo}
	if s.HTTP != nil {
		parts = append(parts, s.HTTP.Title, s.HTTP.Server, s.HTTP.PoweredBy)
		parts = append(parts, s.HTTP.Technologies...)
		for k, v := range s.HTTP.Headers {
			parts = append(parts, k+": "+v)
		}
	}
	return strings.ToLower(strings.Join(parts, " | "))
}

// webClient returns an HTTP client that never follows redirects, skips certificate
// validation and is bound by the target timeout.
func webClient(t *Target) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec // scanning
		DialContext:           (&net.Dialer{Timeout: t.Timeout}).DialContext,
		TLSHandshakeTimeout:   t.Timeout,
		ResponseHeaderTimeout: t.Timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		Proxy:                 nil,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   2 * t.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// webURL builds scheme://ip:port/path for the current service.
func webURL(t *Target, scheme, path string) string {
	return fmt.Sprintf("%s://%s%s", scheme, t.Addr(), path)
}

// webDo performs one request and reads a bounded body.
func webDo(ctx context.Context, c *http.Client, method, url string, body []byte, hdr map[string]string) (*webResp, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; nety)")
	req.Header.Set("Accept", "*/*")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, webMaxBody))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	return &webResp{Status: resp.StatusCode, Header: resp.Header, Body: b, URL: url}, nil
}

// webGetFirst tries GET path on each scheme and returns the first response plus the
// scheme that answered.
func webGetFirst(ctx context.Context, t *Target, c *http.Client, path string, hdr map[string]string) (*webResp, string, error) {
	var lastErr error
	for _, sc := range webSchemes(t.Service) {
		r, err := webDo(ctx, c, http.MethodGet, webURL(t, sc, path), nil, hdr)
		if err == nil {
			return r, sc, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", lastErr
}

var webTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func webTitle(b []byte) string {
	m := webTitleRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(printable(m[1], 120))
}

// webJSON decodes b into v (bounded already) and reports success.
func webJSON(b []byte, v any) bool {
	return json.Unmarshal(b, v) == nil
}

func webPortIs(s model.Service, ports ...int) bool {
	for _, p := range ports {
		if s.Port == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// elasticsearch-no-auth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("elasticsearch-no-auth", "Elasticsearch / OpenSearch API accessible without authentication", model.SevHigh,
			[]string{"elasticsearch", "http"},
			"The Elasticsearch/OpenSearch REST API answers without credentials. Anyone on the network can read (and usually modify or delete) every index, which commonly holds logs, personal data or secrets."),
		Remediation: "Enable the security features (xpack.security.enabled / OpenSearch security plugin) with authentication and TLS, bind the HTTP interface to trusted interfaces only and firewall port 9200.",
		References:  []string{"https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol != model.TCP {
				return false
			}
			if strings.Contains(strings.ToLower(s.Name), "elastic") || strings.Contains(webFingerprintText(s), "elastic") || strings.Contains(webFingerprintText(s), "opensearch") {
				return true
			}
			return webPortIs(s, 9200, 9201) && (webIsHTTP(s) || s.Name == "" || s.Name == "unknown")
		},
		Run: runElasticsearch,
	})
}

func runElasticsearch(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, sc, err := webGetFirst(ctx, t, c, "/", nil)
	if err != nil || r.Status != http.StatusOK {
		return nil
	}
	var root struct {
		Name        string `json:"name"`
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if !webJSON(r.Body, &root) || root.Version.Number == "" || root.ClusterName == "" {
		return nil
	}
	ev := fmt.Sprintf("GET %s -> 200, cluster_name=%q node=%q version=%s %s", r.URL, root.ClusterName, root.Name, root.Version.Distribution, root.Version.Number)
	ri, err := webDo(ctx, c, http.MethodGet, webURL(t, sc, "/_cat/indices?format=json&h=index,docs.count"), nil, nil)
	if err == nil && ri.Status == http.StatusOK {
		var idx []struct {
			Index string `json:"index"`
			Docs  string `json:"docs.count"`
		}
		if webJSON(ri.Body, &idx) {
			names := make([]string, 0, len(idx))
			for _, i := range idx {
				names = append(names, i.Index)
			}
			sort.Strings(names)
			ev += fmt.Sprintf("\nGET /_cat/indices -> %d indices", len(names))
			if len(names) > 0 {
				ev += ": " + strings.Join(limitStrings(names, 25), ", ")
			}
		}
	} else if err == nil {
		ev += fmt.Sprintf("\nGET /_cat/indices -> %d (index listing refused)", ri.Status)
	}
	return []model.Finding{t.Finding(ev)}
}

// ---------------------------------------------------------------------------
// docker-api-unauth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("docker-api-unauth", "Docker Engine API exposed without authentication", model.SevCritical,
			[]string{"docker", "http"},
			"The Docker Engine remote API answers without client certificate authentication. Anyone reaching it can start privileged containers and take full control of the host (root)."),
		Remediation: "Do not expose the Docker socket over TCP. If remote access is required, enable TLS with client certificate verification (--tlsverify) or use SSH transport, and restrict access with a firewall.",
		References:  []string{"https://docs.docker.com/engine/security/protect-access/"},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol != model.TCP {
				return false
			}
			return webPortIs(s, 2375, 2376) || strings.Contains(strings.ToLower(s.Name), "docker") || strings.Contains(webFingerprintText(s), "docker")
		},
		Run: runDockerAPI,
	})
}

func runDockerAPI(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, _, err := webGetFirst(ctx, t, c, "/version", nil)
	if err != nil || r.Status != http.StatusOK {
		return nil
	}
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		Os         string `json:"Os"`
		Arch       string `json:"Arch"`
		Kernel     string `json:"KernelVersion"`
	}
	if !webJSON(r.Body, &v) || v.APIVersion == "" {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf("GET %s -> 200: Docker %s (API %s) %s/%s kernel %s", r.URL, v.Version, v.APIVersion, v.Os, v.Arch, v.Kernel))}
}

// ---------------------------------------------------------------------------
// kubelet-unauth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("kubelet-unauth", "Kubelet API accessible without authentication", model.SevCritical,
			[]string{"kubelet", "https", "http"},
			"The Kubernetes kubelet API (10250, or read-only 10255) answers anonymous requests. On 10250 this usually allows executing commands in every pod of the node; the read-only port leaks pod specifications, which frequently include secrets in environment variables."),
		Remediation: "Set --anonymous-auth=false and --authorization-mode=Webhook on the kubelet, disable the read-only port (--read-only-port=0) and firewall kubelet ports from non-control-plane hosts.",
		References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/"},
		Applies: func(t *Target) bool {
			return t.Service.Protocol == model.TCP && webPortIs(t.Service, 10250, 10255)
		},
		Run: runKubelet,
	})
}

func runKubelet(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, _, err := webGetFirst(ctx, t, c, "/pods", nil)
	if err != nil || r.Status != http.StatusOK {
		return nil
	}
	var pods struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if !webJSON(r.Body, &pods) && !bytes.Contains(r.Body, []byte(`"PodList"`)) {
		return nil
	}
	if pods.Kind != "PodList" && !bytes.Contains(r.Body, []byte(`"PodList"`)) {
		return nil
	}
	names := make([]string, 0, len(pods.Items))
	for _, p := range pods.Items {
		names = append(names, p.Metadata.Namespace+"/"+p.Metadata.Name)
	}
	sort.Strings(names)
	ev := fmt.Sprintf("GET %s -> 200 PodList", r.URL)
	if len(names) > 0 {
		ev += fmt.Sprintf(" (%d pods: %s)", len(names), strings.Join(limitStrings(names, 15), ", "))
	} else if len(r.Body) >= webMaxBody {
		ev += " (response truncated)"
	}
	f := t.Finding(ev)
	if t.Service.Port == 10255 {
		f.Severity = model.SevHigh
		f.Evidence += "\nread-only kubelet port: pod specs (env, mounts) disclosed"
	}
	return []model.Finding{f}
}

// --------------------------------------------------------------------------- etcd-unauth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("etcd-unauth", "etcd key-value store accessible without authentication", model.SevHigh,
			[]string{"etcd", "http"},
			"The etcd client API answers key-value requests without authentication. etcd often stores Kubernetes cluster state, including every Secret."),
		Remediation: "Enable client certificate authentication (--client-cert-auth) and/or etcd RBAC (etcdctl auth enable), and restrict port 2379 to the control plane.",
		References:  []string{"https://etcd.io/docs/latest/op-guide/security/"},
		Applies: func(t *Target) bool {
			s := t.Service
			return s.Protocol == model.TCP && (webPortIs(s, 2379) || strings.Contains(strings.ToLower(s.Name), "etcd"))
		},
		Run: runEtcd,
	})
}

func runEtcd(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, sc, err := webGetFirst(ctx, t, c, "/version", nil)
	if err != nil || r.Status != http.StatusOK {
		return nil
	}
	var ver struct {
		Server  string `json:"etcdserver"`
		Cluster string `json:"etcdcluster"`
	}
	if !webJSON(r.Body, &ver) || ver.Server == "" {
		return nil
	}
	// count_only range over the whole keyspace: read-only, returns no data.
	body := []byte(`{"key":"AA==","range_end":"AA==","count_only":true}`)
	for _, p := range []string{"/v3/kv/range", "/v3beta/kv/range", "/v3alpha/kv/range"} {
		rr, err := webDo(ctx, c, http.MethodPost, webURL(t, sc, p), body, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return nil
		}
		if rr.Status == http.StatusNotFound {
			continue
		}
		var res struct {
			Header *json.RawMessage `json:"header"`
			Count  json.Number      `json:"count"`
			Error  string           `json:"error"`
		}
		if rr.Status == http.StatusOK && webJSON(rr.Body, &res) && res.Header != nil && res.Error == "" {
			cnt := res.Count.String()
			if cnt == "" {
				cnt = "0"
			}
			return []model.Finding{t.Finding(fmt.Sprintf("etcd %s (cluster %s): POST %s count_only over whole keyspace -> 200, count=%s (no authentication)", ver.Server, ver.Cluster, p, cnt))}
		}
		return nil
	}
	// etcd v2 API
	rr, err := webDo(ctx, c, http.MethodGet, webURL(t, sc, "/v2/keys/"), nil, nil)
	if err == nil && rr.Status == http.StatusOK && bytes.Contains(rr.Body, []byte(`"node"`)) {
		return []model.Finding{t.Finding(fmt.Sprintf("etcd %s: GET /v2/keys/ -> 200 (no authentication)", ver.Server))}
	}
	return nil
}

// ---------------------------------------------------------------------------
// couchdb-no-auth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("couchdb-no-auth", "CouchDB accessible without authentication (admin party)", model.SevHigh,
			[]string{"couchdb", "http"},
			"The CouchDB server lists its databases to anonymous users, which usually means it runs in 'admin party' mode or with public databases."),
		Remediation: "Create an admin user, require valid users ([chttpd] require_valid_user = true) and restrict network access to port 5984.",
		References:  []string{"https://docs.couchdb.org/en/stable/intro/security.html"},
		Applies: func(t *Target) bool {
			s := t.Service
			return s.Protocol == model.TCP && (webPortIs(s, 5984, 6984) || strings.Contains(strings.ToLower(s.Name), "couchdb") || strings.Contains(webFingerprintText(s), "couchdb"))
		},
		Run: runCouchDB,
	})
}

func runCouchDB(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, sc, err := webGetFirst(ctx, t, c, "/", nil)
	if err != nil || r.Status != http.StatusOK || !bytes.Contains(r.Body, []byte(`"couchdb"`)) {
		return nil
	}
	rd, err := webDo(ctx, c, http.MethodGet, webURL(t, sc, "/_all_dbs"), nil, nil)
	if err != nil || rd.Status != http.StatusOK {
		return nil
	}
	var dbs []string
	if !webJSON(rd.Body, &dbs) {
		return nil
	}
	sort.Strings(dbs)
	return []model.Finding{t.Finding(fmt.Sprintf("GET /_all_dbs -> 200, %d databases: %s", len(dbs), strings.Join(limitStrings(dbs, 25), ", ")))}
}

// ---------------------------------------------------------------------------
// jenkins-unauth-script-console
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("jenkins-unauth-script-console", "Jenkins script console accessible without authentication", model.SevCritical,
			[]string{"http", "https"},
			"The Jenkins Groovy script console (/script) is reachable anonymously. It allows arbitrary code execution on the Jenkins controller and access to every stored credential."),
		Remediation: "Enable Jenkins security (matrix or role based authorization), remove Overall/Administer and Overall/RunScripts from anonymous users and restrict network access.",
		References:  []string{"https://www.jenkins.io/doc/book/managing/script-console/"},
		Applies: func(t *Target) bool {
			s := t.Service
			if !webIsHTTP(s) && !webPortIs(s, 8080) {
				return false
			}
			if webHeader(s, "X-Jenkins") != "" || strings.Contains(webFingerprintText(s), "jenkins") {
				return true
			}
			return s.HTTP == nil && webPortIs(s, 8080)
		},
		Run: runJenkinsScript,
	})
}

func runJenkinsScript(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, _, err := webGetFirst(ctx, t, c, "/script", nil)
	if err != nil || r.Status != http.StatusOK {
		return nil
	}
	body := string(r.Body)
	if r.Header.Get("X-Jenkins") == "" && !strings.Contains(body, "Jenkins") {
		return nil
	}
	if !strings.Contains(body, "Script Console") || !strings.Contains(body, "script") {
		return nil
	}
	if strings.Contains(body, "j_username") || strings.Contains(body, "loginForm") {
		return nil
	}
	ev := fmt.Sprintf("GET %s -> 200 'Script Console' without authentication", r.URL)
	if v := r.Header.Get("X-Jenkins"); v != "" {
		ev += " (Jenkins " + v + ")"
	}
	return []model.Finding{t.Finding(ev)}
}

// --------------------------------------------------------------------------- shared
// helpers ---------------------------------------------------------------------------

type engineCheckInfo = engine.CheckInfo

// intrusiveInfo marks a catalog entry as intrusive (login attempts).
func intrusiveInfo(i engineCheckInfo) engineCheckInfo { i.Intrusive = true; return i }

func checkInfo(id, title string, sev model.Severity, services []string, desc string) engineCheckInfo {
	return engineCheckInfo{ID: id, Title: title, Severity: sev, Services: services, Description: desc}
}

func limitStrings(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("… (+%d)", len(s)-n))
}

// readWithDeadline sets a fresh read deadline then reads.
func readWithDeadline(c net.Conn, d time.Duration, b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	return c.Read(b)
}
