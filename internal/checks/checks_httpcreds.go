package checks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: intrusiveInfo(checkInfo("http-default-credentials", "Web application accepts default credentials", model.SevCritical,
			[]string{"http", "https"},
			"A web administration interface accepts the username and password its vendor ships it with. The credentials tried are chosen by the product NETY recognised on the port, so each product is only ever offered its own documented defaults and nothing is tried blind. At most three attempts are made per product and "+
				"twelve per host in total, which keeps every attempt count below the lockout thresholds these products use. Products covered: Tomcat, Grafana, RabbitMQ, ActiveMQ, Nexus, MinIO, Zabbix, Nagios, Cacti, LibreNMS, pfSense, Dell iDRAC, Synology, Ubiquiti, Splunk, Elasticsearch, Airflow, Superset, Keycloak, phpMyAdmin, SonarQube, Solr, Artifactory, HashiCorp Vault in dev mode, and the web interfaces of HP, Xerox, Ricoh, Brother and Kyocera printers.")),
		Remediation: "Change the default credentials immediately, disable or remove unused administration consoles and restrict them to an administration network. Treat anything the account could reach as compromised until proven otherwise: these interfaces are usually found by someone else first.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1392.html",
			"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
		},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol != model.TCP {
				return false
			}
			return webIsHTTP(s) || webPortIs(s, httpCredPorts...)
		},
		Run: runHTTPDefaultCreds,
	})
}

// httpCredPorts are the ports the products below listen on when the
// fingerprinter could not name the service.
var httpCredPorts = []int{
	3000, 5000, 5001, 8000, 8080, 8081, 8088, 8089, 8090, 8161, 8200, 8443,
	8983, 9000, 9001, 9090, 9200, 15672,
}

// httpCredMaxPerProduct bounds the attempts against any single product. Every
// product below locks out at five failures or does not lock out at all, so
// three leaves room for an operator's own earlier attempts in the same day.
const httpCredMaxPerProduct = 3

// httpCredApp is one product: how to recognise it, and the credentials its
// vendor documents. Recognition comes first and gates everything else, so a
// product is never offered another product's passwords.
type httpCredApp struct {
	name   string
	detect func(fp string, s model.Service) bool
	try    func(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool)
}

func fpHas(words ...string) func(string, model.Service) bool {
	return func(fp string, _ model.Service) bool {
		for _, w := range words {
			if strings.Contains(fp, w) {
				return true
			}
		}
		return false
	}
}

func fpHasOrPort(words []string, ports ...int) func(string, model.Service) bool {
	has := fpHas(words...)
	return func(fp string, s model.Service) bool {
		return has(fp, s) || webPortIs(s, ports...)
	}
}

var httpCredApps = []httpCredApp{
	{"tomcat", httpCredIsTomcat, httpCredTomcat},
	{"grafana", fpHas("grafana"), httpCredGrafana},
	{"rabbitmq", fpHasOrPort([]string{"rabbitmq"}, 15672), httpCredRabbitMQ},
	{"idrac", fpHas("idrac", "integrated dell remote access"), httpCredIDRAC},
	{"activemq", fpHasOrPort([]string{"activemq"}, 8161), httpCredActiveMQ},
	{"nexus", fpHas("nexus", "sonatype"), httpCredNexus},
	{"minio", fpHas("minio"), httpCredMinIO},
	{"zabbix", fpHas("zabbix"), httpCredZabbix},
	{"nagios", fpHas("nagios"), httpCredNagios},
	{"cacti", fpHas("cacti"), httpCredCacti},
	{"librenms", fpHas("librenms"), httpCredLibreNMS},
	{"pfsense", fpHas("pfsense"), httpCredPfSense},
	{"synology", fpHasOrPort([]string{"synology", "diskstation"}, 5000, 5001), httpCredSynology},
	{"ubiquiti", fpHas("unifi", "ubnt", "ubiquiti", "airos"), httpCredUbiquiti},
	{"splunk", fpHasOrPort([]string{"splunk"}, 8089), httpCredSplunk},
	{"elasticsearch", fpHasOrPort([]string{"elasticsearch", "opensearch"}, 9200), httpCredElasticsearch},
	{"airflow", fpHas("airflow"), httpCredAirflow},
	{"superset", fpHasOrPort([]string{"superset"}, 8088), httpCredSuperset},
	{"keycloak", fpHas("keycloak"), httpCredKeycloak},
	{"phpmyadmin", fpHas("phpmyadmin"), httpCredPHPMyAdmin},
	{"sonarqube", fpHas("sonarqube"), httpCredSonarQube},
	{"solr", fpHasOrPort([]string{"solr"}, 8983), httpCredSolr},
	{"artifactory", fpHas("artifactory", "jfrog"), httpCredArtifactory},
	{"vault", fpHasOrPort([]string{"hashicorp vault", "vault"}, 8200), httpCredVault},
	{"printer", httpCredIsPrinter, httpCredPrinter},
}

func httpCredIsTomcat(fp string, s model.Service) bool {
	return strings.Contains(fp, "tomcat") || strings.Contains(fp, "coyote")
}

func httpCredIsPrinter(fp string, s model.Service) bool {
	for _, m := range printerVendorMarkers {
		if strings.Contains(fp, m) {
			return true
		}
	}
	return false
}

func httpBasic(user, pass string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
}

func httpForm() map[string]string {
	return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
}

func httpJSON() map[string]string { return map[string]string{"Content-Type": "application/json"} }

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
		fp += " | " + strings.ToLower(webTitle(r.Body)+" "+r.Header.Get("Server")+" "+r.Header.Get("X-Powered-By")+" "+r.Header.Get("WWW-Authenticate"))
		fp += " " + httpCredBodyHints(r.Body)
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

// httpCredBodyHints adds the product names that only appear in the page body
// to the fingerprint text, lowercased so detection stays case insensitive.
func httpCredBodyHints(body []byte) string {
	var hints []string
	for _, name := range []string{
		"Grafana", "RabbitMQ", "Apache Tomcat", "iDRAC", "ActiveMQ", "Nexus Repository",
		"MinIO", "Zabbix", "Nagios", "Cacti", "LibreNMS", "pfSense", "Synology",
		"UniFi", "airOS", "Splunk", "Elasticsearch", "OpenSearch", "Airflow",
		"Superset", "Keycloak", "phpMyAdmin", "SonarQube", "Solr", "Artifactory", "Vault",
	} {
		if bytes.Contains(body, []byte(name)) {
			hints = append(hints, strings.ToLower(name))
		}
	}
	return strings.Join(hints, " ")
}

// ---------------------------------------------------------------------------
// Shared attempt helpers
//
// Every attempt passes through t.credAttempt, which holds the per-host
// ceiling. Once it is spent the helpers stop trying rather than falling back
// to another path, so adding products to the table above can never raise the
// number of failed logons a host sees.
// ---------------------------------------------------------------------------

// httpCredBasicAt tries Basic credentials against the first path that
// actually challenges for them. Requiring the challenge first is what keeps
// an endpoint that answers 200 to everyone from being read as a successful
// login.
func httpCredBasicAt(ctx context.Context, t *Target, c *http.Client, scheme, product string, paths []string, marker string, creds [][2]string) (string, bool) {
	for _, p := range paths {
		if ctx.Err() != nil {
			return "", false
		}
		u := webURL(t, scheme, p)
		r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
		if err != nil {
			return "", false
		}
		if r.Status != http.StatusUnauthorized || !strings.Contains(strings.ToLower(r.Header.Get("WWW-Authenticate")), "basic") {
			continue
		}
		for i, cr := range creds {
			if i >= httpCredMaxPerProduct || !t.credAttempt() {
				return "", false
			}
			rr, err := webDo(ctx, c, http.MethodGet, u, nil, httpBasic(cr[0], cr[1]))
			if err != nil {
				return "", false
			}
			if rr.Status != http.StatusOK {
				continue
			}
			if marker != "" && !bytes.Contains(rr.Body, []byte(marker)) {
				continue
			}
			return fmt.Sprintf("%s: GET %s with Basic %s accepted (HTTP 200%s)", product, u, httpCredPair(cr), httpCredMarkerNote(marker)), true
		}
		return "", false
	}
	return "", false
}

// httpCredPost sends one login request on a credential the caller already
// reserved budget for.
func httpCredPost(ctx context.Context, t *Target, c *http.Client, u string, body []byte, hdr map[string]string) (*webResp, bool) {
	if !t.credAttempt() {
		return nil, false
	}
	r, err := webDo(ctx, c, http.MethodPost, u, body, hdr)
	if err != nil {
		return nil, false
	}
	return r, true
}

func httpCredPair(cr [2]string) string {
	if cr[1] == "" {
		return fmt.Sprintf("%s with an empty password", cr[0])
	}
	return cr[0] + ":" + cr[1]
}

func httpCredMarkerNote(marker string) string {
	if marker == "" {
		return ""
	}
	return fmt.Sprintf(", response contains %q", marker)
}

// httpCredSessionSet reports whether the response set a session cookie whose
// name contains want: the sign that a form login was accepted.
func httpCredSessionSet(r *webResp, want string) bool {
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(sc), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Per product attempts
// ---------------------------------------------------------------------------

// Tomcat Manager: Basic auth on /manager/html. LockOutRealm locks a user
// after 5 failures by default: at most 3 attempts.
func httpCredTomcat(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/manager/html")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status != http.StatusUnauthorized || !strings.Contains(strings.ToLower(r.Header.Get("WWW-Authenticate")), "basic") {
		return "", false
	}
	for _, cr := range [][2]string{{"tomcat", "tomcat"}, {"admin", "admin"}, {"tomcat", "s3cret"}} {
		if !t.credAttempt() {
			return "", false
		}
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
	r, ok := httpCredPost(ctx, t, c, u, body, httpJSON())
	if !ok || r.Status != http.StatusOK {
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
	if !t.credAttempt() {
		return "", false
	}
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
	if !t.credAttempt() {
		return "", false
	}
	rr, err := webDo(ctx, c, http.MethodGet, u, nil, httpBasic("root", "calvin"))
	if err != nil || rr.Status != http.StatusOK || !bytes.Contains(rr.Body, []byte("Members")) {
		return "", false
	}
	return fmt.Sprintf("iDRAC Redfish GET %s accepts root:calvin (HTTP 200)", u), true
}

// ActiveMQ: the web console is behind Jetty Basic auth, defaults admin:admin
// and user:user.
func httpCredActiveMQ(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "ActiveMQ console",
		[]string{"/admin/", "/api/jolokia/read/java.lang:type=Runtime"}, "",
		[][2]string{{"admin", "admin"}, {"user", "user"}})
}

// Nexus Repository: admin:admin123 on 3.x before the random password, and on
// every 2.x install.
func httpCredNexus(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Nexus Repository",
		[]string{"/service/rest/v1/security/users", "/service/local/users"}, "",
		[][2]string{{"admin", "admin123"}, {"admin", "admin"}})
}

// MinIO: the console login API, default minioadmin:minioadmin.
func httpCredMinIO(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/api/v1/login")
	body, _ := json.Marshal(map[string]string{"accessKey": "minioadmin", "secretKey": "minioadmin"})
	r, ok := httpCredPost(ctx, t, c, u, body, httpJSON())
	if !ok {
		return "", false
	}
	if (r.Status != http.StatusOK && r.Status != http.StatusNoContent) || !httpCredSessionSet(r, "token") {
		return "", false
	}
	return fmt.Sprintf("MinIO console POST %s accepts minioadmin:minioadmin (HTTP %d, session token issued)", u, r.Status), true
}

// Zabbix: the frontend ships Admin:zabbix.
func httpCredZabbix(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/index.php")
	form := url.Values{"name": {"Admin"}, "password": {"zabbix"}, "autologin": {"1"}, "enter": {"Sign in"}}
	r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
	if !ok {
		return "", false
	}
	if !httpCredSessionSet(r, "zbx_session") || bytes.Contains(r.Body, []byte("Incorrect user name or password")) {
		return "", false
	}
	return fmt.Sprintf("Zabbix POST %s accepts Admin:zabbix (HTTP %d, zbx_session issued)", u, r.Status), true
}

// Nagios Core: the CGI interface is behind Basic auth as nagiosadmin.
func httpCredNagios(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Nagios",
		[]string{"/nagios/cgi-bin/tac.cgi", "/cgi-bin/nagios3/tac.cgi", "/nagios/"}, "",
		[][2]string{{"nagiosadmin", "nagiosadmin"}, {"nagiosadmin", "nagios"}, {"nagiosadmin", "admin"}})
}

// Cacti: admin:admin on a fresh install.
func httpCredCacti(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/index.php")
	form := url.Values{"action": {"login"}, "login_username": {"admin"}, "login_password": {"admin"}}
	r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
	if !ok {
		return "", false
	}
	if bytes.Contains(r.Body, []byte("Invalid User Name")) || bytes.Contains(r.Body, []byte("Authentication Failed")) {
		return "", false
	}
	if !httpCredSessionSet(r, "Cacti") && !strings.Contains(r.Header.Get("Location"), "graph_view.php") {
		return "", false
	}
	return fmt.Sprintf("Cacti POST %s accepts admin:admin (HTTP %d, Location %q)", u, r.Status, r.Header.Get("Location")), true
}

// LibreNMS: the packaged images ship librenms:librenms.
func httpCredLibreNMS(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/login")
	form := url.Values{"username": {"librenms"}, "password": {"librenms"}}
	r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
	if !ok || r.Status != http.StatusFound {
		return "", false
	}
	loc := r.Header.Get("Location")
	if strings.Contains(loc, "/login") || !httpCredSessionSet(r, "librenms_session") {
		return "", false
	}
	return fmt.Sprintf("LibreNMS POST %s accepts librenms:librenms (HTTP 302 to %q)", u, loc), true
}

var pfSenseCSRFRe = regexp.MustCompile(`name=['"]__csrf_magic['"]\s+value=['"]([^'"]+)['"]`)

// pfSense: admin:pfsense. The login form carries a CSRF token, so one GET is
// needed before the single attempt.
func httpCredPfSense(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/index.php")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status != http.StatusOK {
		return "", false
	}
	m := pfSenseCSRFRe.FindSubmatch(r.Body)
	if m == nil {
		return "", false
	}
	cookie := strings.SplitN(r.Header.Get("Set-Cookie"), ";", 2)[0]
	form := url.Values{
		"__csrf_magic": {string(m[1])},
		"usernamefld":  {"admin"},
		"passwordfld":  {"pfsense"},
		"login":        {"Sign In"},
	}
	hdr := httpForm()
	if cookie != "" {
		hdr["Cookie"] = cookie
	}
	rr, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), hdr)
	if !ok {
		return "", false
	}
	if bytes.Contains(rr.Body, []byte("Username or Password incorrect")) {
		return "", false
	}
	if rr.Status != http.StatusFound && rr.Status != http.StatusMovedPermanently {
		return "", false
	}
	return fmt.Sprintf("pfSense POST %s accepts admin:pfsense (HTTP %d to %q)", u, rr.Status, rr.Header.Get("Location")), true
}

// Synology DSM: the setup wizard creates admin with an empty password, and
// plenty of appliances are never taken past that point.
func httpCredSynology(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&account=admin&passwd=&session=nety&format=sid")
	if !t.credAttempt() {
		return "", false
	}
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status != http.StatusOK {
		return "", false
	}
	var res struct {
		Success bool `json:"success"`
		Data    struct {
			SID string `json:"sid"`
		} `json:"data"`
	}
	if !webJSON(r.Body, &res) || !res.Success || res.Data.SID == "" {
		return "", false
	}
	return fmt.Sprintf("Synology DSM %s accepts the account 'admin' with an empty password (a session id was issued)", webURL(t, scheme, "/webapi/auth.cgi")), true
}

// Ubiquiti: ubnt:ubnt on airOS radios and on a UniFi controller that was
// never taken through its setup.
func httpCredUbiquiti(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/api/login")
	body, _ := json.Marshal(map[string]string{"username": "ubnt", "password": "ubnt"})
	if r, ok := httpCredPost(ctx, t, c, u, body, httpJSON()); ok && r.Status == http.StatusOK && bytes.Contains(r.Body, []byte(`"rc":"ok"`)) {
		return fmt.Sprintf("UniFi controller POST %s accepts ubnt:ubnt (HTTP 200 rc=ok)", u), true
	}
	ua := webURL(t, scheme, "/login.cgi")
	form := url.Values{"username": {"ubnt"}, "password": {"ubnt"}, "uri": {"/"}}
	r, ok := httpCredPost(ctx, t, c, ua, []byte(form.Encode()), httpForm())
	if !ok || !httpCredSessionSet(r, "AIROS_SESSION") {
		return "", false
	}
	return fmt.Sprintf("airOS POST %s accepts ubnt:ubnt (HTTP %d, AIROS session issued)", ua, r.Status), true
}

// Splunk: admin:changeme on every release before 7.1.
func httpCredSplunk(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/services/auth/login")
	form := url.Values{"username": {"admin"}, "password": {"changeme"}}
	r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
	if !ok || r.Status != http.StatusOK || !bytes.Contains(r.Body, []byte("<sessionKey>")) {
		return "", false
	}
	return fmt.Sprintf("Splunk POST %s accepts admin:changeme (a session key was returned)", u), true
}

// Elasticsearch / OpenSearch: elastic:changeme on 5.x and 6.x, and
// admin:admin on an OpenSearch demo configuration.
func httpCredElasticsearch(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Elasticsearch",
		[]string{"/_cluster/health", "/"}, "cluster_name",
		[][2]string{{"elastic", "changeme"}, {"elastic", "elastic"}, {"admin", "admin"}})
}

// Airflow: airflow:airflow from the quick start, exercised through the stable
// REST API so no CSRF token is needed.
func httpCredAirflow(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Airflow",
		[]string{"/api/v1/dags", "/api/v1/config"}, "",
		[][2]string{{"airflow", "airflow"}, {"admin", "admin"}})
}

// Superset: admin:admin from the quick start.
func httpCredSuperset(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/api/v1/security/login")
	body, _ := json.Marshal(map[string]any{"username": "admin", "password": "admin", "provider": "db", "refresh": false})
	r, ok := httpCredPost(ctx, t, c, u, body, httpJSON())
	if !ok || r.Status != http.StatusOK {
		return "", false
	}
	var res struct {
		AccessToken string `json:"access_token"`
	}
	if !webJSON(r.Body, &res) || res.AccessToken == "" {
		return "", false
	}
	return fmt.Sprintf("Superset POST %s accepts admin:admin (an access token was returned)", u), true
}

// Keycloak: admin:admin, the bootstrap account of the container images.
func httpCredKeycloak(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	form := url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {"admin"},
	}
	for _, p := range []string{"/realms/master/protocol/openid-connect/token", "/auth/realms/master/protocol/openid-connect/token"} {
		u := webURL(t, scheme, p)
		r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
		if !ok {
			return "", false
		}
		if r.Status == http.StatusNotFound {
			continue
		}
		var res struct {
			AccessToken string `json:"access_token"`
		}
		if r.Status == http.StatusOK && webJSON(r.Body, &res) && res.AccessToken != "" {
			return fmt.Sprintf("Keycloak POST %s accepts admin:admin on the master realm (an access token was returned)", u), true
		}
		return "", false
	}
	return "", false
}

var phpMyAdminTokenRe = regexp.MustCompile(`name=['"]token['"]\s+value=['"]([^'"]+)['"]`)

// phpMyAdmin: the account it signs in with is the database's, and the stock
// XAMPP and WAMP builds leave MySQL root without a password. Only that one
// combination is tried.
func httpCredPHPMyAdmin(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	base := webURL(t, scheme, "/index.php")
	r, err := webDo(ctx, c, http.MethodGet, base, nil, nil)
	if err != nil || r.Status != http.StatusOK {
		return "", false
	}
	m := phpMyAdminTokenRe.FindSubmatch(r.Body)
	if m == nil {
		return "", false
	}
	cookie := strings.SplitN(r.Header.Get("Set-Cookie"), ";", 2)[0]
	form := url.Values{"pma_username": {"root"}, "pma_password": {""}, "token": {string(m[1])}}
	hdr := httpForm()
	if cookie != "" {
		hdr["Cookie"] = cookie
	}
	rr, ok := httpCredPost(ctx, t, c, base, []byte(form.Encode()), hdr)
	if !ok {
		return "", false
	}
	if bytes.Contains(rr.Body, []byte("Access denied")) || bytes.Contains(rr.Body, []byte("#1045")) {
		return "", false
	}
	if rr.Status != http.StatusFound || !strings.Contains(rr.Header.Get("Location"), "index.php") {
		return "", false
	}
	return fmt.Sprintf("phpMyAdmin POST %s signs in as MySQL root with an empty password (HTTP 302 to %q)", base, rr.Header.Get("Location")), true
}

// SonarQube: admin:admin until the first password change is forced.
func httpCredSonarQube(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/api/authentication/login")
	form := url.Values{"login": {"admin"}, "password": {"admin"}}
	r, ok := httpCredPost(ctx, t, c, u, []byte(form.Encode()), httpForm())
	if !ok || (r.Status != http.StatusOK && r.Status != http.StatusNoContent) {
		return "", false
	}
	if !httpCredSessionSet(r, "JWT-SESSION") {
		return "", false
	}
	return fmt.Sprintf("SonarQube POST %s accepts admin:admin (HTTP %d, JWT session issued)", u, r.Status), true
}

// Solr: the reference guide's example security.json ships solr:SolrRocks, and
// it is copied into real deployments as often as it is read.
func httpCredSolr(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Solr",
		[]string{"/solr/admin/info/system?wt=json", "/solr/admin/cores?wt=json"}, "",
		[][2]string{{"solr", "SolrRocks"}})
}

// Artifactory: admin:password, the documented first-login credential.
func httpCredArtifactory(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	return httpCredBasicAt(ctx, t, c, scheme, "Artifactory",
		[]string{"/artifactory/api/system/version", "/artifactory/api/security/users"}, "",
		[][2]string{{"admin", "password"}})
}

// HashiCorp Vault in dev mode: the root token is literally "root", and an
// unsealed dev server on a network is a secret store with no secrets kept.
func httpCredVault(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	u := webURL(t, scheme, "/v1/sys/mounts")
	r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
	if err != nil || r.Status == http.StatusOK {
		// A Vault that answers without a token is not a default credential.
		return "", false
	}
	if !t.credAttempt() {
		return "", false
	}
	rr, err := webDo(ctx, c, http.MethodGet, u, nil, map[string]string{"X-Vault-Token": "root"})
	if err != nil || rr.Status != http.StatusOK || !bytes.Contains(rr.Body, []byte("secret/")) {
		return "", false
	}
	return fmt.Sprintf("HashiCorp Vault GET %s accepts the development root token \"root\": the server is running in dev mode with its secret engines readable", u), true
}

// httpCredPrinterDefaults holds each vendor's documented administrator
// credential. A printer is only offered the credentials of the vendor whose
// name is in its own fingerprint.
var httpCredPrinterDefaults = []struct {
	vendor string
	words  []string
	paths  []string
	creds  [][2]string
}{
	{"HP", []string{"hp http server", "hp laserjet", "hp officejet", "jetdirect"},
		[]string{"/hp/device/SignIn/Index", "/"}, [][2]string{{"admin", "admin"}, {"admin", ""}}},
	{"Xerox", []string{"xerox", "workcentre", "versalink", "altalink"},
		[]string{"/properties/", "/"}, [][2]string{{"admin", "1111"}, {"admin", "11111"}, {"11111", "x-admin"}}},
	{"Ricoh", []string{"ricoh", "savin", "lanier"},
		[]string{"/web/guest/en/websys/webArch/mainFrame.cgi", "/"}, [][2]string{{"admin", ""}, {"admin", "password"}}},
	{"Brother", []string{"brother"},
		[]string{"/general/status.html", "/"}, [][2]string{{"admin", "access"}, {"admin", "initpass"}}},
	{"Kyocera", []string{"kyocera"},
		[]string{"/startwlm/Start_Wlm.htm", "/"}, [][2]string{{"Admin", "Admin"}, {"admin", "admin"}, {"2800", "2800"}}},
}

func httpCredPrinter(ctx context.Context, t *Target, c *http.Client, scheme string) (string, bool) {
	fp := webFingerprintText(t.Service)
	for _, v := range httpCredPrinterDefaults {
		match := false
		for _, w := range v.words {
			if strings.Contains(fp, w) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if ev, ok := httpCredBasicAt(ctx, t, c, scheme, v.vendor+" printer", v.paths, "", v.creds); ok {
			return ev, true
		}
	}
	return "", false
}
