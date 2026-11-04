package checks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: intrusiveInfo(checkInfo("http-default-credentials", "Web application accepts default credentials", model.SevCritical,
			[]string{"http", "https"},
			"A web administration interface accepts a well-known vendor default username/password. Products covered: Apache Tomcat Manager, Grafana, RabbitMQ management, Dell iDRAC (Redfish). At most three attempts are made per service to avoid account lockouts.")),
		Remediation: "Change the default credentials immediately, disable or remove unused administration consoles and restrict them to an administration network.",
		References:  []string{"https://cwe.mitre.org/data/definitions/1392.html", "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
		Applies: func(t *Target) bool {
			return webIsHTTP(t.Service) || webPortIs(t.Service, 15672, 3000)
		},
		Run: runHTTPDefaultCreds,
	})
}

type httpCredApp struct {
	name   string
	detect func(fp string, s model.Service) bool
	try    func(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool)
}

var httpCredApps = []httpCredApp{
	{"tomcat", httpCredIsTomcat, httpCredTomcat},
	{"grafana", func(fp string, s model.Service) bool { return strings.Contains(fp, "grafana") }, httpCredGrafana},
	{"rabbitmq", func(fp string, s model.Service) bool { return strings.Contains(fp, "rabbitmq") || s.Port == 15672 }, httpCredRabbitMQ},
	{"idrac", func(fp string, s model.Service) bool {
		return strings.Contains(fp, "idrac") || strings.Contains(fp, "integrated dell remote access")
	}, httpCredIDRAC},
}

func httpCredIsTomcat(fp string, s model.Service) bool {
	return strings.Contains(fp, "tomcat") || strings.Contains(fp, "coyote")
}

func httpBasic(user, pass string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
}

func runHTTPDefaultCreds(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	fp := webFingerprintText(t.Service)
	schemes := webSchemes(t.Service)
	scheme := schemes[0]
	if t.Service.HTTP == nil {
		// One unauthenticated GET / to recognise the product.
		r, sc, err := webGetFirst(ctx, t, c, "/", nil)
		if err != nil {
			return nil
		}
		scheme = sc
		fp += " | " + strings.ToLower(webTitle(r.Body)+" "+r.Header.Get("Server")+" "+r.Header.Get("X-Powered-By"))
		if bytes.Contains(r.Body, []byte("grafana")) || bytes.Contains(r.Body, []byte("Grafana")) {
			fp += " grafana"
		}
		if bytes.Contains(r.Body, []byte("RabbitMQ")) {
			fp += " rabbitmq"
		}
		if bytes.Contains(r.Body, []byte("Apache Tomcat")) {
			fp += " tomcat"
		}
		if bytes.Contains(r.Body, []byte("iDRAC")) {
			fp += " idrac"
		}
	}
	for _, app := range httpCredApps {
		if ctx.Err() != nil {
			return nil
		}
		if !app.detect(fp, t.Service) {
			continue
		}
		if ev, ok := app.try(ctx, t, c, scheme); ok {
			f := t.Finding(ev)
			f.Title = "Default credentials accepted (" + app.name + ")"
			return []model.Finding{f}
		}
	}
	return nil
}

// Tomcat Manager: Basic auth on /manager/html. LockOutRealm locks a user
// after 5 failures by default: at most 3 attempts.
func httpCredTomcat(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/manager/html")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status != http.StatusUnauthorized || !strings.Contains(strings.ToLower(r.Header.Get("WWW-Authenticate")), "basic") {
		return "", false
	}
	for _, cr := range [][2]string{{"tomcat", "tomcat"}, {"admin", "admin"}, {"tomcat", "s3cret"}} {
		rr, err := webDo(ctx, c, http.MethodGet, u, nil, httpBasic(cr[0], cr[1]))
		if err != nil {
			return "", false
		}
		if rr.Status == http.StatusOK && (bytes.Contains(rr.Body, []byte("Tomcat Web Application Manager")) || bytes.Contains(rr.Body, []byte("/manager/html/"))) {
			return fmt.Sprintf("Tomcat Manager %s accepts %s:%s (HTTP 200)", u, cr[0], cr[1]), true
		}
		if rr.Status == http.StatusForbidden {
			// Valid credentials but missing manager-gui role: still a finding.
			return fmt.Sprintf("Tomcat %s: %s:%s authenticated (HTTP 403, user lacks manager-gui role)", u, cr[0], cr[1]), true
		}
	}
	return "", false
}

// Grafana: POST /login {"user":"admin","password":"admin"} -> 200 "Logged in".
func httpCredGrafana(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/login")
	body, _ := json.Marshal(map[string]string{"user": "admin", "password": "admin"})
	r, err := webDo(ctx, c, http.MethodPost, u, body, map[string]string{"Content-Type": "application/json"})
	if err != nil || r.Status != http.StatusOK {
		return "", false
	}
	var res struct {
		Message string `json:"message"`
	}
	if !webJSON(r.Body, &res) || !strings.Contains(strings.ToLower(res.Message), "logged in") {
		return "", false
	}
	return fmt.Sprintf("Grafana POST %s accepts admin:admin (%q)", u, res.Message), true
}

// RabbitMQ management: GET /api/whoami with guest:guest.
func httpCredRabbitMQ(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/api/whoami")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, httpBasic("guest", "guest"))
	if err != nil || r.Status != http.StatusOK {
		return "", false
	}
	var res struct {
		Name string `json:"name"`
		Tags any    `json:"tags"`
	}
	if !webJSON(r.Body, &res) || res.Name != "guest" {
		return "", false
	}
	return fmt.Sprintf("RabbitMQ management GET %s accepts guest:guest (tags: %v)", u, res.Tags), true
}

// Dell iDRAC: Redfish GET /redfish/v1/Systems with root:calvin.
func httpCredIDRAC(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/redfish/v1/Systems")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status != http.StatusUnauthorized {
		return "", false
	}
	rr, err := webDo(ctx, c, http.MethodGet, u, nil, httpBasic("root", "calvin"))
	if err != nil || rr.Status != http.StatusOK || !bytes.Contains(rr.Body, []byte("Members")) {
		return "", false
	}
	return fmt.Sprintf("iDRAC Redfish GET %s accepts root:calvin (HTTP 200)", u), true
}
