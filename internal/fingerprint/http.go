package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"

	"github.com/GoToolSharing/nety/internal/model"
)

const (
	httpUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	maxHTTPBody    = 512 << 10 // hard cap on the body we read and hash
	maxFaviconBody = 512 << 10
	maxHeaderVal   = 512
	maxHeaders     = 48
)

// httpResult is the outcome of the HTTP layer.
type httpResult struct {
	info   *model.HTTPInfo
	banner []byte // reconstructed status line + headers
	body   []byte
	header http.Header
}

func (d *dialer) httpClient() *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.dial(ctx)
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := d.dialTLS(ctx, []string{"http/1.1"})
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		TLSClientConfig:        clientTLSConfig(d.hostname, []string{"http/1.1"}),
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{}, // no HTTP/2
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout:  d.timeout,
		TLSHandshakeTimeout:    d.timeout,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   2 * d.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (d *dialer) baseURL(useTLS bool) *url.URL {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host := d.ip.String()
	if d.hostname != "" {
		host = d.hostname
	}
	defPort := (useTLS && d.port == 443) || (!useTLS && d.port == 80)
	if !defPort {
		host = net.JoinHostPort(host, strconv.Itoa(int(d.port)))
	} else if d.ip.Is6() && d.hostname == "" {
		host = "[" + host + "]"
	}
	return &url.URL{Scheme: scheme, Host: host, Path: "/"}
}

func newRequest(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return req, nil
}

// probeHTTP sends GET / and analyses the response. It returns an error when the service
// does not speak HTTP.
func (d *dialer) probeHTTP(ctx context.Context, useTLS bool) (*httpResult, error) {
	client := d.httpClient()
	defer client.CloseIdleConnections()
	base := d.baseURL(useTLS)
	req, err := newRequest(ctx, base.String())
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	_ = resp.Body.Close()

	info := &model.HTTPInfo{
		Scheme:        base.Scheme,
		URL:           base.String(),
		StatusCode:    resp.StatusCode,
		Server:        truncate(cleanText(resp.Header.Get("Server")), maxHeaderVal),
		PoweredBy:     truncate(cleanText(resp.Header.Get("X-Powered-By")), maxHeaderVal),
		Location:      truncate(resp.Header.Get("Location"), 2048),
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Headers:       selectHeaders(resp.Header),
		AuthSchemes:   authSchemes(resp.Header.Values("WWW-Authenticate")),
		Title:         extractTitle(body),
	}
	if info.ContentLength < 0 {
		info.ContentLength = int64(len(body))
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		info.BodySHA256 = hex.EncodeToString(sum[:])
	}
	if icon := d.fetchFavicon(ctx, client, base, body); icon != nil {
		info.FaviconMMH3 = faviconHash(icon)
	}
	info.Technologies = detectTech(resp.Header, body, info.Title)
	return &httpResult{info: info, banner: rawHead(resp), body: body, header: resp.Header}, nil
}

func rawHead(resp *http.Response) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			if k == "Set-Cookie" {
				// Never keep a session value: the cookie NAME is the only part worth
				// reporting.
				name, _, _ := strings.Cut(v, "=")
				fmt.Fprintf(&b, "%s: %s=<redacted>\r\n", k, strings.TrimSpace(name))
				continue
			}
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	return b.Bytes()
}

func selectHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(keys), maxHeaders))
	for _, k := range keys {
		if len(out) >= maxHeaders {
			break
		}
		vals := h[k]
		if k == "Set-Cookie" {
			// keep cookie names only: values may be session secrets
			names := make([]string, 0, len(vals))
			for _, v := range vals {
				n, _, _ := strings.Cut(v, "=")
				names = append(names, strings.TrimSpace(n))
			}
			out[k] = truncate(strings.Join(names, ", "), maxHeaderVal)
			continue
		}
		out[k] = truncate(cleanText(strings.Join(vals, ", ")), maxHeaderVal)
	}
	return out
}

var authSchemeRe = regexp.MustCompile(`(?i)(?:^|,)\s*(basic|digest|ntlm|negotiate|bearer|kerberos|mutual|hoba|aws4-hmac-sha256|scram-sha-256)\b`)

var authSchemeCanon = map[string]string{
	"basic": "Basic", "digest": "Digest", "ntlm": "NTLM", "negotiate": "Negotiate",
	"bearer": "Bearer", "kerberos": "Kerberos", "mutual": "Mutual", "hoba": "HOBA",
	"aws4-hmac-sha256": "AWS4-HMAC-SHA256", "scram-sha-256": "SCRAM-SHA-256",
}

func authSchemes(values []string) []string {
	var out []string
	for _, v := range values {
		matched := false
		for _, m := range authSchemeRe.FindAllStringSubmatch(v, -1) {
			matched = true
			s := authSchemeCanon[strings.ToLower(m[1])]
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
		if !matched {
			if f := strings.Fields(v); len(f) > 0 && !slices.Contains(out, f[0]) {
				out = append(out, f[0])
			}
		}
	}
	return out
}

// extractTitle returns the first <title> text of an HTML document.
func extractTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			name, _ := z.TagName()
			if string(name) != "title" {
				continue
			}
			var sb strings.Builder
			for {
				tt := z.Next()
				if tt == html.TextToken {
					sb.Write(z.Text())
					continue
				}
				break
			}
			return normalizeTitle(sb.String())
		}
	}
}

func normalizeTitle(s string) string {
	if !utf8.ValidString(s) {
		s = latin1ToUTF8([]byte(s))
	}
	return truncate(cleanText(s), 256)
}

func latin1ToUTF8(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// faviconHref finds the first <link rel="...icon..." href="..."> in body.
func faviconHref(body []byte) string {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return ""
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) == "body" {
			return ""
		}
		if string(name) != "link" || !hasAttr {
			continue
		}
		var rel, href string
		for {
			k, v, more := z.TagAttr()
			switch string(k) {
			case "rel":
				rel = strings.ToLower(string(v))
			case "href":
				href = strings.TrimSpace(string(v))
			}
			if !more {
				break
			}
		}
		if href != "" && strings.Contains(rel, "icon") && !strings.Contains(rel, "mask") {
			return href
		}
	}
}

func (d *dialer) fetchFavicon(ctx context.Context, client *http.Client, base *url.URL, body []byte) []byte {
	candidates := []string{}
	if href := faviconHref(body); href != "" && !strings.HasPrefix(href, "data:") {
		if u, err := base.Parse(href); err == nil && u.Host == base.Host && u.Scheme == base.Scheme {
			candidates = append(candidates, u.String())
		}
	}
	def := base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String()
	if !slices.Contains(candidates, def) {
		candidates = append(candidates, def)
	}
	for _, u := range candidates {
		if ctx.Err() != nil {
			return nil
		}
		req, err := newRequest(ctx, u)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxFaviconBody))
		_ = resp.Body.Close()
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if resp.StatusCode != http.StatusOK || len(data) == 0 {
			continue
		}
		isSVG := strings.Contains(ct, "svg")
		looksHTML := strings.Contains(ct, "text/html") || bytes.HasPrefix(bytes.TrimSpace(data), []byte("<"))
		if isSVG || !looksHTML {
			return data
		}
	}
	return nil
}

// serverProduct maps a Server header to nmap-style product/version/info/OS and CPEs.
type serverProduct struct {
	Product, Version, Extra, OS string
	CPEs                        []string
}

type serverRule struct {
	re      *regexp.Regexp
	product string
	cpe     string // version appended when known
	os      string
}

var serverRules = []serverRule{
	{regexp.MustCompile(`^Apache-Coyote/([\d.]+)`), "Apache Tomcat/Coyote JSP engine", "cpe:/a:apache:coyote_http_connector", ""},
	{regexp.MustCompile(`^Apache(?:/([\d.]+))?`), "Apache httpd", "cpe:/a:apache:http_server", ""},
	{regexp.MustCompile(`^nginx(?:/([\d.]+))?`), "nginx", "cpe:/a:igor_sysoev:nginx", ""},
	{regexp.MustCompile(`^openresty(?:/([\d.]+))?`), "OpenResty web app server", "cpe:/a:openresty:ngx_openresty", ""},
	{regexp.MustCompile(`^Microsoft-IIS(?:/([\d.]+))?`), "Microsoft IIS httpd", "cpe:/a:microsoft:internet_information_services", "Windows"},
	{regexp.MustCompile(`^Microsoft-HTTPAPI(?:/([\d.]+))?`), "Microsoft HTTPAPI httpd", "cpe:/o:microsoft:windows", "Windows"},
	{regexp.MustCompile(`^lighttpd(?:/([\d.]+))?`), "lighttpd", "cpe:/a:lighttpd:lighttpd", ""},
	{regexp.MustCompile(`^Jetty\(([^)]+)\)`), "Jetty", "cpe:/a:eclipse:jetty", ""},
	{regexp.MustCompile(`^Kestrel`), "Microsoft Kestrel httpd", "cpe:/a:microsoft:kestrel", ""},
	{regexp.MustCompile(`^Caddy`), "Caddy httpd", "cpe:/a:caddyserver:caddy", ""},
	{regexp.MustCompile(`^LiteSpeed`), "LiteSpeed httpd", "cpe:/a:litespeedtech:litespeed_web_server", ""},
	{regexp.MustCompile(`^gunicorn(?:/([\d.]+))?`), "Gunicorn", "cpe:/a:gunicorn:gunicorn", ""},
	{regexp.MustCompile(`^Werkzeug/([\d.]+)`), "Werkzeug httpd", "cpe:/a:palletsprojects:werkzeug", ""},
	{regexp.MustCompile(`^SimpleHTTP/([\d.]+)`), "SimpleHTTPServer", "cpe:/a:python:python", ""},
	{regexp.MustCompile(`^BaseHTTP/([\d.]+)`), "BaseHTTPServer", "cpe:/a:python:python", ""},
	{regexp.MustCompile(`^TornadoServer/([\d.]+)`), "Tornado httpd", "cpe:/a:tornadoweb:tornado", ""},
	{regexp.MustCompile(`^CherryPy/([\d.]+)`), "CherryPy httpd", "cpe:/a:cherrypy:cherrypy", ""},
	{regexp.MustCompile(`^uvicorn`), "Uvicorn", "cpe:/a:encode:uvicorn", ""},
	{regexp.MustCompile(`^HP-iLO-Server(?:/([\d.]+))?`), "HP Integrated Lights-Out web server", "cpe:/h:hp:integrated_lights-out", ""},
	{regexp.MustCompile(`^HP HTTP Server`), "HP HTTP Server", "", ""},
	{regexp.MustCompile(`^Mbedthis-Appweb(?:/([\d.]+))?`), "Mbedthis-Appweb", "cpe:/a:mbedthis:appweb", ""},
	{regexp.MustCompile(`^GoAhead-Webs`), "GoAhead WebServer", "cpe:/a:goahead:goahead_webserver", ""},
	{regexp.MustCompile(`^Boa(?:/([\d.rc]+))?`), "Boa HTTPd", "cpe:/a:boa:boa", ""},
	{regexp.MustCompile(`^thttpd(?:/([\d.]+\w*))?`), "thttpd", "cpe:/a:acme:thttpd", ""},
	{regexp.MustCompile(`^mini_httpd(?:/([\d.]+))?`), "mini_httpd", "cpe:/a:acme:mini_httpd", ""},
	{regexp.MustCompile(`^squid(?:/([\d.]+\w*))?`), "Squid http proxy", "cpe:/a:squid-cache:squid", ""},
	{regexp.MustCompile(`^Oracle-HTTP-Server`), "Oracle HTTP Server", "cpe:/a:oracle:http_server", ""},
	{regexp.MustCompile(`^IBM_HTTP_Server`), "IBM HTTP Server", "cpe:/a:ibm:http_server", ""},
	{regexp.MustCompile(`^WebLogic`), "Oracle WebLogic Server", "cpe:/a:oracle:weblogic_server", ""},
	{regexp.MustCompile(`^Splunkd`), "Splunkd httpd", "cpe:/a:splunk:splunk", ""},
	{regexp.MustCompile(`^Kibana`), "Kibana", "cpe:/a:elastic:kibana", ""},
	{regexp.MustCompile(`^CouchDB/([\d.]+)`), "CouchDB httpd", "cpe:/a:apache:couchdb", ""},
	{regexp.MustCompile(`^Embedthis-http`), "Embedthis HTTP lib httpd", "", ""},
	{regexp.MustCompile(`^cloudflare`), "Cloudflare http proxy", "", ""},
	{regexp.MustCompile(`^AkamaiGHost`), "Akamai GHost", "", ""},
	{regexp.MustCompile(`^Virata-EmWeb(?:/R([\d_]+))?`), "Virata-EmWeb", "", ""},
	{regexp.MustCompile(`^RomPager(?:/([\d.]+))?`), "Allegro RomPager", "cpe:/a:allegrosoft:rompager", ""},
	{regexp.MustCompile(`^Zope(?:/\(Zope ([\d.]+))?`), "Zope httpd", "cpe:/a:zope:zope", ""},
	{regexp.MustCompile(`^Node\.js`), "Node.js", "cpe:/a:nodejs:node.js", ""},
	{regexp.MustCompile(`^Tengine(?:/([\d.]+))?`), "Tengine httpd", "cpe:/a:alibaba:tengine", ""},
	{regexp.MustCompile(`^Envoy|^envoy`), "Envoy proxy", "cpe:/a:envoyproxy:envoy", ""},
	{regexp.MustCompile(`^Traefik`), "Traefik", "cpe:/a:traefik:traefik", ""},
}

var osHints = []struct {
	needle, os string
}{
	{"win32", "Windows"}, {"win64", "Windows"}, {"windows", "Windows"},
	{"ubuntu", "Linux"}, {"debian", "Linux"}, {"centos", "Linux"}, {"red hat", "Linux"},
	{"fedora", "Linux"}, {"suse", "Linux"}, {"rocky", "Linux"}, {"almalinux", "Linux"},
	{"amazon", "Linux"}, {"unix", "Unix"}, {"freebsd", "FreeBSD"}, {"openbsd", "OpenBSD"},
}

var genericServerRe = regexp.MustCompile(`^([A-Za-z][\w.\-]*)(?:/v?(\d[\w.\-]*))?\s*(.*)$`)

func parseServerHeader(s string) serverProduct {
	s = strings.TrimSpace(s)
	var sp serverProduct
	if s == "" {
		return sp
	}
	matched := false
	for _, r := range serverRules {
		m := r.re.FindStringSubmatchIndex(s)
		if m == nil {
			continue
		}
		matched = true
		sp.Product = r.product
		if len(m) >= 4 && m[2] >= 0 {
			sp.Version = s[m[2]:m[3]]
		}
		sp.Extra = strings.TrimSpace(s[m[1]:])
		sp.OS = r.os
		if r.cpe != "" {
			c := r.cpe
			if sp.Version != "" && strings.HasPrefix(c, "cpe:/a:") {
				c += ":" + sp.Version
			}
			sp.CPEs = append(sp.CPEs, c)
		}
		break
	}
	if !matched {
		if m := genericServerRe.FindStringSubmatch(s); m != nil {
			sp.Product, sp.Version, sp.Extra = m[1], m[2], strings.TrimSpace(m[3])
		} else {
			sp.Product = truncate(s, 128)
		}
	}
	sp.Extra = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sp.Extra), "-"))
	if sp.OS == "" {
		low := strings.ToLower(s)
		for _, h := range osHints {
			if strings.Contains(low, h.needle) {
				sp.OS = h.os
				break
			}
		}
	}
	sp.Extra = truncate(sp.Extra, 200)
	return sp
}
