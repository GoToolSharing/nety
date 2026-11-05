package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// adminConsole is one application server management console. They are all found the same
// way (recognise the product, then ask the management entry point whether it answers an
// anonymous client), so they share a runner and differ only in the table below.
type adminConsole struct {
	id          string
	title       string
	severity    model.Severity
	services    []string
	description string
	remediation string
	references  []string
	// ports are the ports the product listens on by default. A service with no HTTP
	// fingerprint on one of them is probed anyway, because the port scan often reaches
	// these before the fingerprinter has anything to say.
	ports []int
	// keywords match the service fingerprint (title, Server header, product).
	keywords []string
	// probe returns the evidence and the severity that the observation deserves, or
	// ok=false when the console is protected.
	probe func(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool)
}

var adminConsoles = []adminConsole{
	{
		id:          "tomcat-manager-unauth",
		title:       "Tomcat manager application reachable without authentication",
		severity:    model.SevHigh,
		services:    []string{"http", "https"},
		description: "The Tomcat manager (or host-manager) application answers without asking for credentials. The manager deploys web applications: anyone who reaches it can upload a WAR and run code as the Tomcat user, which on most servers is enough to read every application's configuration and its database credentials. Tomcat ships these applications disabled, so finding one open means it was enabled deliberately and the access rules were never finished.",
		remediation: "Remove the manager and host-manager applications from any server that does not need them. Where they are needed, keep them behind a role in tomcat-users.xml with a strong password and restrict access with the RemoteAddrValve to the administration network.",
		references: []string{
			"https://tomcat.apache.org/tomcat-10.0-doc/manager-howto.html",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		ports:    []int{8080, 8443, 8180, 80, 443},
		keywords: []string{"tomcat", "coyote"},
		probe:    probeTomcatManager,
	},
	{
		id:          "jboss-management-unauth",
		title:       "JBoss / WildFly management interface reachable without authentication",
		severity:    model.SevCritical,
		services:    []string{"http", "https"},
		description: "The JBoss or WildFly management interface answers an anonymous client. That interface deploys applications and reads the server configuration, including the datasource passwords, so unauthenticated access to it is code execution on the host and the credentials for whatever the applications talk to. The older jmx-console is the same problem by another route: it invokes MBeans directly, and the deployment MBeans are reachable from it.",
		remediation: "Add a management user (add-user.sh) and make sure the management interfaces require authentication, bind them to the management address rather than to 0.0.0.0, and remove the legacy jmx-console and web-console applications from any JBoss AS that still ships them.",
		references: []string{
			"https://docs.wildfly.org/26/Admin_Guide.html#Management_tasks",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		ports:    []int{9990, 9999, 8080, 8180, 9443},
		keywords: []string{"jboss", "wildfly", "jbossweb", "undertow"},
		probe:    probeJBossManagement,
	},
	{
		id:          "weblogic-console-exposed",
		title:       "Oracle WebLogic administration console reachable",
		severity:    model.SevMedium,
		services:    []string{"http", "https"},
		description: "The Oracle WebLogic administration console is reachable from this network. The console itself asks for a password, but reaching it is the precondition for most of what has gone wrong with WebLogic: the console and the T3/IIOP endpoints beside it have carried a long run of unauthenticated deserialisation bugs that are exploited before any login, and weblogic/welcome1 is still found in the field. An administration console has no business being reachable from a user VLAN.",
		remediation: "Restrict the console to the administration network, and in production disable it entirely (set the domain's console-enabled to false, administration is then done through WLST). Keep the quarterly patch updates current and restrict the T3 and IIOP protocols with a connection filter.",
		references: []string{
			"https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/secmg/secure.html",
			"https://cwe.mitre.org/data/definitions/1327.html",
		},
		ports:    []int{7001, 7002},
		keywords: []string{"weblogic"},
		probe:    probeWebLogicConsole,
	},
	{
		id:          "portainer-unauth",
		title:       "Portainer reachable without authentication",
		severity:    model.SevCritical,
		services:    []string{"http", "https"},
		description: "Portainer answers management requests without a token, or has never had its administrator account created. Portainer drives the Docker or Kubernetes engine behind it, so either state means whoever reaches it can start a privileged container and own the host; an uninitialised instance is worse, because the first person to find it simply chooses the administrator password.",
		remediation: "Create the administrator account immediately on any instance that has none, and never leave a fresh deployment reachable before that is done. Restrict the Portainer port to the administration network, put it behind TLS and a reverse proxy that authenticates, and review the environments it has access to.",
		references: []string{
			"https://docs.portainer.io/admin/settings",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		ports:    []int{9000, 9443, 9001},
		keywords: []string{"portainer"},
		probe:    probePortainer,
	},
	{
		id:          "rancher-unauth",
		title:       "Rancher API reachable without authentication",
		severity:    model.SevHigh,
		services:    []string{"http", "https"},
		description: "The Rancher management API answers without a token. Rancher holds the kubeconfig for every cluster it manages, so an unauthenticated API is not one cluster but all of them, together with the registry credentials and the cloud credentials stored alongside them.",
		remediation: "Finish the Rancher bootstrap so the API requires authentication, and check that no authentication provider was left disabled. Restrict the Rancher server to the administration network and rotate every cluster and cloud credential it holds if it was reachable.",
		references: []string{
			"https://ranchermanager.docs.rancher.com/api/quickstart",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		ports:    []int{443, 8443, 80, 8080},
		keywords: []string{"rancher"},
		probe:    probeRancher,
	},
}

func init() {
	for i := range adminConsoles {
		ac := adminConsoles[i]
		register(&Check{
			Info:        checkInfo(ac.id, ac.title, ac.severity, ac.services, ac.description),
			Remediation: ac.remediation,
			References:  ac.references,
			Applies:     func(t *Target) bool { return ac.applies(t) },
			Run: func(ctx context.Context, t *Target) []model.Finding {
				return ac.run(ctx, t)
			},
		})
	}
}

func (ac adminConsole) applies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP {
		return false
	}
	if !webIsHTTP(s) && !webPortIs(s, ac.ports...) {
		return false
	}
	fp := webFingerprintText(s)
	for _, k := range ac.keywords {
		if strings.Contains(fp, k) {
			return true
		}
	}
	// No usable fingerprint: the default port is the only hint there is.
	return s.HTTP == nil && webPortIs(s, ac.ports...)
}

func (ac adminConsole) run(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	for _, sc := range webSchemes(t.Service) {
		if ctx.Err() != nil {
			return nil
		}
		ev, sev, ok := ac.probe(ctx, t, c, sc)
		if !ok {
			continue
		}
		f := t.Finding(ev)
		if sev != "" {
			f.Severity = sev
		}
		return []model.Finding{f}
	}
	return nil
}

// probeTomcatManager asks the manager applications for their own start page. A protected
// manager answers 401, which is not reported here: credentials for it are the business of
// the gated default-credential check.
func probeTomcatManager(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool) {
	for _, p := range []struct{ path, marker string }{
		{"/manager/html", "Tomcat Web Application Manager"},
		{"/host-manager/html", "Tomcat Virtual Host Manager"},
		{"/manager/text/list", "OK - Listed applications for virtual host"},
	} {
		r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, p.path), nil, nil)
		if err != nil {
			return "", "", false
		}
		if r.Status != http.StatusOK || !bytes.Contains(r.Body, []byte(p.marker)) {
			continue
		}
		return fmt.Sprintf("GET %s -> 200 with %q in the body, served without any Authorization header.", webURL(t, scheme, p.path), p.marker), "", true
	}
	return "", "", false
}

func probeJBossManagement(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool) {
	// WildFly's HTTP management endpoint answers a GET with the root resource when no
	// security realm is configured on it.
	r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/management"), nil, nil)
	if err != nil {
		return "", "", false
	}
	if r.Status == http.StatusOK {
		var root map[string]any
		if webJSON(r.Body, &root) {
			if _, ok := root["management-major-version"]; ok {
				return fmt.Sprintf("GET %s -> 200 and the management root resource was returned without authentication (product %v, management version %v.%v).",
					webURL(t, scheme, "/management"), root["product-name"], root["management-major-version"], root["management-minor-version"]), "", true
			}
		}
	}
	// JBoss AS 4 to 6: the JMX console invokes MBeans directly.
	rj, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/jmx-console/"), nil, nil)
	if err != nil {
		return "", "", false
	}
	if rj.Status == http.StatusOK && (bytes.Contains(rj.Body, []byte("JMX Agent View")) || bytes.Contains(rj.Body, []byte("jboss.system"))) {
		return fmt.Sprintf("GET %s -> 200 'JMX Agent View' without authentication: MBeans, including the deployment MBeans, are invokable anonymously.", webURL(t, scheme, "/jmx-console/")), "", true
	}
	return "", "", false
}

func probeWebLogicConsole(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool) {
	for _, p := range []string{"/console/login/LoginForm.jsp", "/console/"} {
		r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, p), nil, nil)
		if err != nil {
			return "", "", false
		}
		body := r.Body
		if r.Status != http.StatusOK || (!bytes.Contains(body, []byte("WebLogic")) && !bytes.Contains(body, []byte("weblogic"))) {
			continue
		}
		ev := fmt.Sprintf("GET %s -> 200, the WebLogic console login page is served to this network (title %q).\nThe console was not logged into: no credential was sent.",
			webURL(t, scheme, p), webTitle(body))
		return ev, "", true
	}
	return "", "", false
}

func probePortainer(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool) {
	r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/api/status"), nil, nil)
	if err != nil {
		return "", "", false
	}
	var st struct {
		Version  string `json:"Version"`
		Instance string `json:"InstanceID"`
	}
	if r.Status != http.StatusOK || !webJSON(r.Body, &st) || st.Version == "" {
		return "", "", false
	}
	// 404 from this endpoint is Portainer saying no administrator exists yet. It is a
	// read: nothing is created, and the account is not claimed.
	ra, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/api/users/admin/check"), nil, nil)
	if err != nil {
		return "", "", false
	}
	if ra.Status == http.StatusNotFound {
		return fmt.Sprintf("Portainer %s at %s has no administrator account yet (GET /api/users/admin/check -> 404).\nAnyone reaching this instance can create the administrator and take over the Docker or Kubernetes environments behind it. No account was created by this check.",
			st.Version, t.Addr()), model.SevCritical, true
	}
	// An initialised instance should refuse an untokened API request.
	re, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/api/endpoints"), nil, nil)
	if err != nil {
		return "", "", false
	}
	if re.Status == http.StatusOK && bytes.HasPrefix(bytes.TrimSpace(re.Body), []byte("[")) && bytes.Contains(re.Body, []byte(`"Type"`)) {
		return fmt.Sprintf("Portainer %s at %s answered GET /api/endpoints with 200 and the environment list without a JWT or an API key.",
			st.Version, t.Addr()), model.SevCritical, true
	}
	return "", "", false
}

func probeRancher(ctx context.Context, t *Target, c *http.Client, scheme string) (string, model.Severity, bool) {
	// /v3-public is unauthenticated by design and must not count. /v3 is the
	// authenticated API, so a collection from it means the API is open.
	r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/v3"), nil, nil)
	if err != nil {
		return "", "", false
	}
	var api struct {
		Type   string         `json:"type"`
		Links  map[string]any `json:"links"`
		Data   []any          `json:"data"`
		Status int            `json:"status"`
	}
	if r.Status != http.StatusOK || !webJSON(r.Body, &api) {
		return "", "", false
	}
	if api.Type != "collection" && api.Type != "apiRoot" && api.Type != "schema" {
		return "", "", false
	}
	if len(api.Links) == 0 {
		return "", "", false
	}
	names := make([]string, 0, len(api.Links))
	for k := range api.Links {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Sprintf("GET %s -> 200 %q without an Authorization header; the API root lists %d resource links (%s).",
		webURL(t, scheme, "/v3"), api.Type, len(api.Links), strings.Join(limitStrings(names, 12), ", ")), "", true
}
