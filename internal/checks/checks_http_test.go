package checks

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// --------------------------------------------------------------------------- Harness for
// the HTTP checks
// ---------------------------------------------------------------------------

// httpFake serves h on loopback and returns the port it bound.
func httpFake(t *testing.T, h http.Handler) int {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, p, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("test server address %q: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("test server port %q: %v", p, err)
	}
	return port
}

// webSvc describes an HTTP service the fingerprinter has already looked at.
func webSvc(port int, title, server string) model.Service {
	s := tcpSvc("http", port)
	s.HTTP = &model.HTTPInfo{Scheme: "http", StatusCode: 200, Title: title, Server: server}
	return s
}

// routes turns a path to handler map into a mux that 404s everything else.
func routes(m map[string]http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	for p, h := range m {
		mux.HandleFunc(p, h)
	}
	return mux
}

func writeString(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	writeString(w, status, body)
}

// ---------------------------------------------------------------------------
// spring-boot-actuator
// ---------------------------------------------------------------------------

func TestSpringBootActuator(t *testing.T) {
	t.Run("env and heapdump exposed", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/actuator": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"heapdump":{"href":"/actuator/heapdump"},"mappings":{"href":"/actuator/mappings"}}}`)
			},
			"/actuator/env": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig","properties":{"spring.datasource.password":{"value":"hunter2"}}}]}`)
			},
			"/actuator/heapdump": func(w http.ResponseWriter, r *http.Request) {
				t.Error("the check requested /actuator/heapdump: generating a heap dump stops the JVM")
				writeString(w, 200, "")
			},
		}))
		fs := probe(t, "spring-boot-actuator", webSvc(port, "app", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevCritical {
			t.Errorf("severity = %s, want critical", fs[0].Severity)
		}
		for _, want := range []string{"heapdump", "propertySources", "deliberately not requested"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
		if strings.Contains(fs[0].Evidence, "hunter2") {
			t.Errorf("the finding copies a secret out of /actuator/env: %q", fs[0].Evidence)
		}
	})

	t.Run("health only is information", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/actuator": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}`)
			},
		}))
		fs := probe(t, "spring-boot-actuator", webSvc(port, "app", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevInfo {
			t.Errorf("a bare health endpoint should be info, got %s", fs[0].Severity)
		}
	})

	t.Run("boot 1.x endpoints", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/env": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"profiles":[],"systemProperties":{"java.version":"1.8.0"}}`)
			},
			"/health": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"status":"UP"}`) },
		}))
		fs := probe(t, "spring-boot-actuator", webSvc(port, "app", "Apache-Coyote/1.1"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevCritical {
			t.Errorf("severity = %s, want critical for /env", fs[0].Severity)
		}
	})

	t.Run("actuator protected", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, r *http.Request) { writeString(w, 401, "unauthorized") },
		}))
		if fs := probe(t, "spring-boot-actuator", webSvc(port, "app", "nginx")); len(fs) != 0 {
			t.Fatalf("protected actuator reported: %+v", fs)
		}
	})

	t.Run("health endpoint alone is not reported on boot 1.x", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/health": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"status":"UP"}`) },
		}))
		if fs := probe(t, "spring-boot-actuator", webSvc(port, "app", "nginx")); len(fs) != 0 {
			t.Fatalf("a lone health probe was reported: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// adcs-web-enrollment and the NTLM family
// ---------------------------------------------------------------------------

// ntlmChallengeHeader is a type 2 message as a server would send it.
func ntlmChallengeHeader() string {
	return "NTLM " + base64.StdEncoding.EncodeToString(smbFakeChallenge())
}

// iisNTLM answers a Windows authentication prompt on the given paths.
func iisNTLM(paths ...string) http.Handler {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !set[r.URL.Path] {
			writeString(w, 404, "Not Found")
			return
		}
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		if strings.HasPrefix(r.Header.Get("Authorization"), "NTLM ") {
			w.Header().Set("WWW-Authenticate", ntlmChallengeHeader())
			writeString(w, 401, "")
			return
		}
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		writeString(w, 401, "")
	})
}

func TestADCSWebEnrollment(t *testing.T) {
	t.Run("ntlm enrolment reachable", func(t *testing.T) {
		port := httpFake(t, iisNTLM("/certsrv/", "/certsrv/certfnsh.asp"))
		fs := probe(t, "adcs-web-enrollment", webSvc(port, "", "Microsoft-IIS/10.0"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		for _, want := range []string{"ESC8", "CORP", "PRINT01", "/certsrv/"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("no ad cs on this host", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, r *http.Request) { writeString(w, 404, "Not Found") },
		}))
		if fs := probe(t, "adcs-web-enrollment", webSvc(port, "", "Microsoft-IIS/10.0")); len(fs) != 0 {
			t.Fatalf("reported without an enrolment application: %+v", fs)
		}
	})

	t.Run("401 from a front end that is not IIS", func(t *testing.T) {
		port := httpFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx")
			w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
			writeString(w, 401, "")
		}))
		if fs := probe(t, "adcs-web-enrollment", webSvc(port, "", "nginx")); len(fs) != 0 {
			t.Fatalf("a catch-all 401 was read as AD CS: %+v", fs)
		}
	})
}

func TestNTLMInfoDisclosure(t *testing.T) {
	t.Run("names disclosed", func(t *testing.T) {
		port := httpFake(t, iisNTLM("/"))
		fs := probe(t, "ntlm-info-disclosure", webSvc(port, "", "Microsoft-IIS/10.0"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevInfo {
			t.Errorf("severity = %s, want info", fs[0].Severity)
		}
		for _, want := range []string{"CORP", "PRINT01", "No credential was sent"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("basic auth only", func(t *testing.T) {
		port := httpFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
			writeString(w, 401, "")
		}))
		if fs := probe(t, "ntlm-info-disclosure", webSvc(port, "", "nginx")); len(fs) != 0 {
			t.Fatalf("a Basic prompt was reported as NTLM disclosure: %+v", fs)
		}
	})
}

func TestWinRMExposed(t *testing.T) {
	t.Run("wsman answers", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/wsman": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
				w.Header().Add("WWW-Authenticate", "Negotiate")
				writeString(w, 401, "")
			},
		}))
		fs := probe(t, "winrm-exposed", tcpSvc("wsman", port))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevInfo {
			t.Errorf("severity = %s, want info", fs[0].Severity)
		}
		if !strings.Contains(fs[0].Evidence, "Microsoft-HTTPAPI") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("something else on the port", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, r *http.Request) { writeString(w, 404, "nope") },
		}))
		if fs := probe(t, "winrm-exposed", tcpSvc("wsman", port)); len(fs) != 0 {
			t.Fatalf("reported without a WS-Management endpoint: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// wsus-over-http
// ---------------------------------------------------------------------------

func TestWSUSOverHTTP(t *testing.T) {
	asmx := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			writeString(w, 200, "<html><head><title>"+name+"</title></head><body>"+
				name+" Web Service<br/>The following operations are supported. soap:address</body></html>")
		}
	}

	t.Run("cleartext wsus", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/ClientWebService/client.asmx":                 asmx("ClientWebService"),
			"/SimpleAuthWebService/SimpleAuth.asmx":         asmx("SimpleAuth"),
			"/ReportingWebService/ReportingWebService.asmx": asmx("ReportingWebService"),
		}))
		fs := probe(t, "wsus-over-http", webSvc(port, "WSUS Administration", "Microsoft-IIS/10.0"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		for _, want := range []string{"ClientWebService", "SimpleAuth", "No WSUS TLS port"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
	})

	t.Run("not a wsus server", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, r *http.Request) { writeString(w, 200, "<html>hello</html>") },
		}))
		if fs := probe(t, "wsus-over-http", webSvc(port, "WSUS Administration", "Microsoft-IIS/10.0")); len(fs) != 0 {
			t.Fatalf("reported against a plain web server: %+v", fs)
		}
	})

	t.Run("tls port is out of scope", func(t *testing.T) {
		c := lookupCheck(t, "wsus-over-http")
		svc := tcpSvc("https", 8531)
		if c.Applies(&Target{Service: svc, Services: []model.Service{svc}}) {
			t.Error("the check must not run on the TLS WSUS port")
		}
	})
}

// ---------------------------------------------------------------------------
// http-vcs-exposed
// ---------------------------------------------------------------------------

func TestHTTPVCSExposed(t *testing.T) {
	t.Run("git and env", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) { writeString(w, 200, "ref: refs/heads/main\n") },
			"/.git/config": func(w http.ResponseWriter, r *http.Request) {
				writeString(w, 200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.corp.local/app.git\n")
			},
			"/.env": func(w http.ResponseWriter, r *http.Request) {
				writeString(w, 200, "APP_ENV=production\nAPP_KEY=base64:abcdef\nDB_PASSWORD=hunter2\n")
			},
		}))
		fs := probe(t, "http-vcs-exposed", webSvc(port, "app", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevHigh {
			t.Errorf("severity = %s, want high", fs[0].Severity)
		}
		for _, want := range []string{"/.git/HEAD", "ref: refs/heads/main", "git.corp.local", "DB_PASSWORD"} {
			if !strings.Contains(fs[0].Evidence, want) {
				t.Errorf("evidence missing %q: %q", want, fs[0].Evidence)
			}
		}
		if strings.Contains(fs[0].Evidence, "hunter2") {
			t.Errorf("the finding copies the secret values out of .env: %q", fs[0].Evidence)
		}
	})

	t.Run("ds_store only is low", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/.DS_Store": func(w http.ResponseWriter, r *http.Request) {
				writeString(w, 200, "\x00\x00\x00\x01Bud1\x00\x00\x00\x00backup")
			},
		}))
		fs := probe(t, "http-vcs-exposed", webSvc(port, "app", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevLow {
			t.Errorf("severity = %s, want low", fs[0].Severity)
		}
	})

	t.Run("catch-all 200 is not a finding", func(t *testing.T) {
		port := httpFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			writeString(w, 200, "<html><body>single page app</body></html>")
		}))
		if fs := probe(t, "http-vcs-exposed", webSvc(port, "app", "nginx")); len(fs) != 0 {
			t.Fatalf("a site that answers 200 for everything was reported: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// administration consoles
// ---------------------------------------------------------------------------

func TestAdminConsolesUnauthenticated(t *testing.T) {
	cases := []struct {
		id      string
		server  string
		title   string
		routes  map[string]http.HandlerFunc
		wantSev model.Severity
		wantEv  string
	}{
		{
			id: "tomcat-manager-unauth", server: "Apache-Coyote/1.1", title: "Apache Tomcat",
			routes: map[string]http.HandlerFunc{
				"/manager/html": func(w http.ResponseWriter, r *http.Request) {
					writeString(w, 200, "<html><title>/manager</title><body>Tomcat Web Application Manager</body></html>")
				},
			},
			wantSev: model.SevHigh, wantEv: "Tomcat Web Application Manager",
		},
		{
			id: "jboss-management-unauth", server: "WildFly/26", title: "WildFly",
			routes: map[string]http.HandlerFunc{
				"/management": func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, 200, `{"product-name":"WildFly Full","management-major-version":17,"management-minor-version":0}`)
				},
			},
			wantSev: model.SevCritical, wantEv: "WildFly Full",
		},
		{
			id: "weblogic-console-exposed", server: "WebLogic Server", title: "Oracle WebLogic Server Administration Console",
			routes: map[string]http.HandlerFunc{
				"/console/login/LoginForm.jsp": func(w http.ResponseWriter, r *http.Request) {
					writeString(w, 200, "<html><title>Oracle WebLogic Server Administration Console</title><body>WebLogic</body></html>")
				},
			},
			wantSev: model.SevMedium, wantEv: "WebLogic console login page",
		},
		{
			id: "portainer-unauth", server: "", title: "Portainer",
			routes: map[string]http.HandlerFunc{
				"/api/status": func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, 200, `{"Version":"2.19.4","InstanceID":"abc"}`)
				},
				"/api/users/admin/check": func(w http.ResponseWriter, r *http.Request) { writeString(w, 404, "") },
			},
			wantSev: model.SevCritical, wantEv: "no administrator account yet",
		},
		{
			id: "rancher-unauth", server: "", title: "Rancher",
			routes: map[string]http.HandlerFunc{
				"/v3": func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, 200, `{"type":"collection","links":{"self":"/v3","clusters":"/v3/clusters","tokens":"/v3/tokens"},"data":[]}`)
				},
			},
			wantSev: model.SevHigh, wantEv: "clusters",
		},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			port := httpFake(t, routes(tc.routes))
			fs := probe(t, tc.id, webSvc(port, tc.title, tc.server))
			if len(fs) != 1 {
				t.Fatalf("want 1 finding, got %d", len(fs))
			}
			if fs[0].Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", fs[0].Severity, tc.wantSev)
			}
			if !strings.Contains(fs[0].Evidence, tc.wantEv) {
				t.Errorf("evidence missing %q: %q", tc.wantEv, fs[0].Evidence)
			}
		})
	}
}

func TestAdminConsolesProtected(t *testing.T) {
	cases := []struct {
		id     string
		server string
		title  string
		routes map[string]http.HandlerFunc
	}{
		{"tomcat-manager-unauth", "Apache-Coyote/1.1", "Apache Tomcat", map[string]http.HandlerFunc{
			"/manager/html": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
				writeString(w, 401, "")
			},
		}},
		{"jboss-management-unauth", "WildFly/26", "WildFly", map[string]http.HandlerFunc{
			"/management": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Digest realm="ManagementRealm"`)
				writeString(w, 401, "")
			},
		}},
		{"weblogic-console-exposed", "WebLogic Server", "WebLogic", map[string]http.HandlerFunc{
			"/console/login/LoginForm.jsp": func(w http.ResponseWriter, r *http.Request) { writeString(w, 404, "") },
		}},
		{"portainer-unauth", "", "Portainer", map[string]http.HandlerFunc{
			"/api/status": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"Version":"2.19.4","InstanceID":"abc"}`)
			},
			"/api/users/admin/check": func(w http.ResponseWriter, r *http.Request) { writeString(w, 204, "") },
			"/api/endpoints":         func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{"message":"unauthorized"}`) },
		}},
		{"rancher-unauth", "", "Rancher", map[string]http.HandlerFunc{
			"/v3": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{"type":"error","status":401}`) },
			"/v3-public/authProviders": func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, `{"type":"collection","links":{"self":"/v3-public/authProviders"},"data":[]}`)
			},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			port := httpFake(t, routes(tc.routes))
			if fs := probe(t, tc.id, webSvc(port, tc.title, tc.server)); len(fs) != 0 {
				t.Fatalf("protected console reported: %+v", fs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// printer-unauth-admin
// ---------------------------------------------------------------------------

func TestPrinterUnauthAdmin(t *testing.T) {
	t.Run("hp device status open", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/hp/device/DeviceStatus/Index": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "HP HTTP Server; HP LaserJet M507")
				writeString(w, 200, "<html><title>Device Status</title><body>DeviceStatus ready</body></html>")
			},
		}))
		fs := probe(t, "printer-unauth-admin", webSvc(port, "HP LaserJet M507", "HP HTTP Server"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevMedium {
			t.Errorf("severity = %s, want medium", fs[0].Severity)
		}
		if !strings.Contains(strings.ToLower(fs[0].Description), "address book") {
			t.Error("the description must explain that printers hold LDAP and SMB credentials")
		}
	})

	t.Run("sign-in page is not open administration", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/hp/device/DeviceStatus/Index": func(w http.ResponseWriter, r *http.Request) {
				writeString(w, 200, "<html><title>Device Status</title><body>Sign In<input type=\"password\"></body></html>")
			},
		}))
		if fs := probe(t, "printer-unauth-admin", webSvc(port, "HP LaserJet", "HP HTTP Server")); len(fs) != 0 {
			t.Fatalf("a sign-in page was reported as unauthenticated administration: %+v", fs)
		}
	})

	t.Run("not a printer", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/": func(w http.ResponseWriter, r *http.Request) { writeString(w, 200, "hello") },
		}))
		if fs := probe(t, "printer-unauth-admin", webSvc(port, "Corporate intranet", "nginx")); len(fs) != 0 {
			t.Fatalf("reported against a host that is not a printer: %+v", fs)
		}
	})
}

// ---------------------------------------------------------------------------
// http-default-credentials: the expanded corpus
// ---------------------------------------------------------------------------

func TestHTTPDefaultCredentialsCorpus(t *testing.T) {
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	t.Run("solr", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/solr/admin/info/system": func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != basic("solr", "SolrRocks") {
					w.Header().Set("WWW-Authenticate", `Basic realm="solr"`)
					writeString(w, 401, "")
					return
				}
				writeJSON(w, 200, `{"lucene":{"solr-spec-version":"9.4.0"}}`)
			},
		}))
		fs := probe(t, "http-default-credentials", webSvc(port, "Solr Admin", "jetty"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if fs[0].Severity != model.SevCritical || !strings.Contains(fs[0].Title, "solr") {
			t.Errorf("finding = %+v", fs[0])
		}
	})

	t.Run("vault dev mode", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/v1/sys/mounts": func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vault-Token") != "root" {
					writeJSON(w, 403, `{"errors":["permission denied"]}`)
					return
				}
				writeJSON(w, 200, `{"secret/":{"type":"kv"},"sys/":{"type":"system"}}`)
			},
		}))
		fs := probe(t, "http-default-credentials", webSvc(port, "Vault", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "dev mode") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("synology blank admin", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/webapi/auth.cgi": func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("account") != "admin" || r.URL.Query().Get("passwd") != "" {
					writeJSON(w, 200, `{"success":false,"error":{"code":400}}`)
					return
				}
				writeJSON(w, 200, `{"success":true,"data":{"sid":"abcd1234"}}`)
			},
		}))
		fs := probe(t, "http-default-credentials", webSvc(port, "Synology DiskStation", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "empty password") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("keycloak", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/realms/master/protocol/openid-connect/token": func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "admin" {
					writeJSON(w, 401, `{"error":"invalid_grant"}`)
					return
				}
				writeJSON(w, 200, `{"access_token":"ey.ey.ey","expires_in":60}`)
			},
		}))
		fs := probe(t, "http-default-credentials", webSvc(port, "Keycloak", "nginx"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "master realm") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("xerox printer", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/properties/": func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != basic("admin", "1111") {
					w.Header().Set("WWW-Authenticate", `Basic realm="Xerox WorkCentre"`)
					writeString(w, 401, "")
					return
				}
				writeString(w, 200, "<html>Properties</html>")
			},
		}))
		fs := probe(t, "http-default-credentials", webSvc(port, "Xerox WorkCentre 7855", "Xerox_MicroServer"))
		if len(fs) != 1 {
			t.Fatalf("want 1 finding, got %d", len(fs))
		}
		if !strings.Contains(fs[0].Evidence, "Xerox printer") {
			t.Errorf("evidence: %q", fs[0].Evidence)
		}
	})

	t.Run("credentials changed", func(t *testing.T) {
		port := httpFake(t, routes(map[string]http.HandlerFunc{
			"/solr/admin/info/system": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="solr"`)
				writeString(w, 401, "")
			},
			"/solr/admin/cores": func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Basic realm="solr"`)
				writeString(w, 401, "")
			},
		}))
		if fs := probe(t, "http-default-credentials", webSvc(port, "Solr Admin", "jetty")); len(fs) != 0 {
			t.Fatalf("a product with changed credentials was reported: %+v", fs)
		}
	})
}

// TestHTTPCredAttemptsAreCapped proves the promise in the check description:
// a product is tried a few times and the host has a ceiling of its own.
func TestHTTPCredAttemptsAreCapped(t *testing.T) {
	var attempts int32
	port := httpFake(t, routes(map[string]http.HandlerFunc{
		"/nagios/cgi-bin/tac.cgi": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				atomic.AddInt32(&attempts, 1)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Nagios Access"`)
			writeString(w, 401, "")
		},
	}))
	if fs := probe(t, "http-default-credentials", webSvc(port, "Nagios Core", "Apache")); len(fs) != 0 {
		t.Fatalf("reported although every credential was refused: %+v", fs)
	}
	if n := atomic.LoadInt32(&attempts); n > httpCredMaxPerProduct {
		t.Fatalf("%d credentials tried against one product, cap is %d", n, httpCredMaxPerProduct)
	}

	b := newCredBudget()
	used := 0
	for b.take() {
		used++
		if used > 2*MaxCredAttemptsPerHost {
			t.Fatal("the per-host budget never runs out")
		}
	}
	if used != MaxCredAttemptsPerHost {
		t.Fatalf("per-host budget granted %d attempts, want %d", used, MaxCredAttemptsPerHost)
	}
	if !(*credBudget)(nil).take() {
		t.Error("a target without a budget must still be able to run (unit tests)")
	}
}

// TestHTTPCredCorpusIsFingerprintDriven keeps the promise that a product is only ever
// offered its own documented defaults.
func TestHTTPCredCorpusIsFingerprintDriven(t *testing.T) {
	seen := map[string]bool{}
	for _, app := range httpCredApps {
		if app.name == "" || app.detect == nil || app.try == nil {
			t.Errorf("incomplete corpus entry %+v", app.name)
		}
		if seen[app.name] {
			t.Errorf("duplicate corpus entry %q", app.name)
		}
		seen[app.name] = true
		// Nothing may match a service it has never been told anything about.
		if app.detect("", model.Service{Port: 1, Protocol: model.TCP}) {
			t.Errorf("%s matches a service with no fingerprint and no default port", app.name)
		}
	}
	desc := New(nil).Catalog()
	for _, c := range desc {
		if c.ID != "http-default-credentials" {
			continue
		}
		for _, want := range []string{"attempt", "per host"} {
			if !strings.Contains(strings.ToLower(c.Description), want) {
				t.Errorf("the description must state the caps (%q missing): %s", want, c.Description)
			}
		}
	}
}

// TestNewChecksAreRegistered lists what this wave added, so a check that is dropped or
// renamed fails here rather than silently leaving the catalog.
func TestNewChecksAreRegistered(t *testing.T) {
	want := map[string]model.Severity{
		"dns-zone-transfer":         model.SevHigh,
		"spring-boot-actuator":      model.SevHigh,
		"adcs-web-enrollment":       model.SevHigh,
		"wsus-over-http":            model.SevHigh,
		"ldap-signing-not-required": model.SevHigh,
		"ms-rprn-spooler":           model.SevMedium,
		"cisco-smart-install":       model.SevHigh,
		"smtp-open-relay":           model.SevMedium,
		"smtp-vrfy-expn":            model.SevMedium,
		"tftp-anonymous-read":       model.SevMedium,
		"printer-unauth-admin":      model.SevMedium,
		"tomcat-manager-unauth":     model.SevHigh,
		"jboss-management-unauth":   model.SevCritical,
		"weblogic-console-exposed":  model.SevMedium,
		"portainer-unauth":          model.SevCritical,
		"rancher-unauth":            model.SevHigh,
		"http-vcs-exposed":          model.SevHigh,
		"winrm-exposed":             model.SevInfo,
		"ntlm-info-disclosure":      model.SevInfo,
		"snmp-write-community":      model.SevMedium,
		"ntp-monlist":               model.SevMedium,
	}
	have := map[string]model.Severity{}
	for _, c := range New(nil).Catalog() {
		have[c.ID] = c.Severity
	}
	for id, sev := range want {
		got, ok := have[id]
		if !ok {
			t.Errorf("check %q is not registered", id)
			continue
		}
		if got != sev {
			t.Errorf("check %q severity = %s, want %s", id, got, sev)
		}
	}
}
