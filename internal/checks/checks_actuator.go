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

func init() {
	register(&Check{
		Info: checkInfo("spring-boot-actuator", "Spring Boot actuator endpoints exposed without authentication", model.SevHigh,
			[]string{"http", "https"},
			"Spring Boot actuator endpoints answer without authentication. Actuators are management endpoints: /env and /configprops print the application's resolved configuration, which on an internal network almost always contains database passwords, LDAP bind credentials, API tokens and message broker secrets; /heapdump hands out the whole JVM heap, from which those same secrets and live session tokens are recovered offline. A reachable actuator turns one web server into the credentials a tester (or an attacker) needs for the rest of the network."),
		Remediation: "Expose only the endpoints the application genuinely needs (management.endpoints.web.exposure.include=health,info), bind the management port to a management interface (management.server.address), and put the remaining endpoints behind authentication with Spring Security. Never expose env, configprops or heapdump to a user network.",
		References: []string{
			"https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
			"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
		},
		Applies: func(t *Target) bool {
			return webIsHTTP(t.Service) || webPortIs(t.Service, 8080, 8081, 8090, 9090, 9001)
		},
		Run: runSpringActuator,
	})
}

// actuatorEndpoint describes one endpoint and what finding it against an
// unauthenticated client means.
type actuatorEndpoint struct {
	name string
	// marker must appear in the body: a 200 alone proves nothing, since many
	// front ends answer 200 with a SPA shell for every path.
	marker string
	sev    model.Severity
	why    string
}

// actuatorBoot1 are the Spring Boot 1.x endpoints, which sit at the root
// instead of under /actuator. Only cheap, read-only ones are requested.
var actuatorBoot1 = []actuatorEndpoint{
	{"env", `"systemProperties"`, model.SevCritical, "resolved configuration including passwords and tokens"},
	{"configprops", `"prefix"`, model.SevHigh, "bound configuration properties"},
	{"beans", `"beans"`, model.SevHigh, "application structure and bean wiring"},
	{"mappings", `"handler"`, model.SevHigh, "every HTTP route of the application"},
	{"trace", `"timestamp"`, model.SevHigh, "recent HTTP requests including Authorization and Cookie headers"},
	{"health", `"status"`, model.SevInfo, "liveness only"},
}

// actuatorSensitive grades the endpoints a Boot 2.x/3.x index advertises.
var actuatorSensitive = map[string]struct {
	sev model.Severity
	why string
}{
	"env":         {model.SevCritical, "resolved configuration including passwords and tokens"},
	"heapdump":    {model.SevCritical, "a full dump of the JVM heap: secrets and live session tokens"},
	"configprops": {model.SevHigh, "bound configuration properties"},
	"jolokia":     {model.SevHigh, "JMX over HTTP, frequently a code execution path"},
	"beans":       {model.SevHigh, "application structure and bean wiring"},
	"mappings":    {model.SevHigh, "every HTTP route of the application"},
	"threaddump":  {model.SevHigh, "thread stacks, which leak in-flight data"},
	"httptrace":   {model.SevHigh, "recent HTTP requests including Authorization and Cookie headers"},
	"loggers":     {model.SevHigh, "runtime log level control"},
	"shutdown":    {model.SevHigh, "stops the application (not exercised)"},
	"metrics":     {model.SevLow, "application metrics"},
	"info":        {model.SevInfo, "build information"},
	"health":      {model.SevInfo, "liveness only"},
}

func runSpringActuator(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	r, scheme, err := webGetFirst(ctx, t, c, "/actuator", nil)
	if err != nil {
		return nil
	}
	if r.Status == http.StatusOK {
		if f := actuatorFromIndex(ctx, t, c, scheme, r); f != nil {
			return []model.Finding{*f}
		}
	}
	return actuatorBoot1Probe(ctx, t, c, scheme)
}

// actuatorFromIndex reads the Boot 2.x/3.x discovery page. The index names
// every exposed endpoint, which is why NETY never has to request /heapdump:
// serving a heap dump forces a full garbage collection and stops the JVM for
// as long as it takes to write the heap out, so asking for one would be a
// performance hit on a production application. Being listed in the index is
// the evidence, and the finding says so.
func actuatorFromIndex(ctx context.Context, t *Target, c *http.Client, scheme string, idx *webResp) *model.Finding {
	var page struct {
		Links map[string]struct {
			Href string `json:"href"`
		} `json:"_links"`
	}
	if !webJSON(idx.Body, &page) || len(page.Links) == 0 {
		return nil
	}
	names := make([]string, 0, len(page.Links))
	for n := range page.Links {
		if n == "self" {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)

	sev := model.SevInfo
	var notes []string
	for _, n := range names {
		g, ok := actuatorSensitive[strings.SplitN(n, "-", 2)[0]]
		if !ok {
			continue
		}
		if sevRank(g.sev) > sevRank(sev) {
			sev = g.sev
		}
		notes = append(notes, fmt.Sprintf("  %-12s %s", n, g.why))
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "GET %s -> 200, Spring Boot actuator discovery page served without authentication.\n", idx.URL)
	fmt.Fprintf(&ev, "Endpoints advertised (%d): %s\n", len(names), strings.Join(limitStrings(names, 30), ", "))
	if len(notes) > 0 {
		ev.WriteString("Of those:\n" + strings.Join(limitStrings(notes, 15), "\n") + "\n")
	}
	// /env is cheap and read-only, so one request confirms that the listing is
	// real rather than an index behind a filter that blocks the endpoints.
	if _, ok := page.Links["env"]; ok {
		if re, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/actuator/env"), nil, nil); err == nil && re.Status == http.StatusOK && bytes.Contains(re.Body, []byte(`"propertySources"`)) {
			fmt.Fprintf(&ev, "GET /actuator/env -> 200 with propertySources (%d bytes read, content not recorded).\n", len(re.Body))
			sev = model.SevCritical
		}
	}
	if _, ok := page.Links["heapdump"]; ok {
		ev.WriteString("/actuator/heapdump is advertised. It was deliberately not requested: generating a heap dump stops the JVM while the heap is written out.\n")
	}
	f := t.Finding(strings.TrimRight(ev.String(), "\n"))
	f.Severity = sev
	if sev == model.SevInfo {
		f.Title = "Spring Boot actuator discovery page reachable without authentication"
	}
	return &f
}

// actuatorBoot1Probe covers Spring Boot 1.x, where the endpoints live at the
// root and there is no index to read.
func actuatorBoot1Probe(ctx context.Context, t *Target, c *http.Client, scheme string) []model.Finding {
	sev := model.SevInfo
	var lines []string
	for _, e := range actuatorBoot1 {
		if ctx.Err() != nil {
			break
		}
		r, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/"+e.name), nil, nil)
		if err != nil || r.Status != http.StatusOK {
			continue
		}
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.Contains(ct, "json") || !bytes.Contains(r.Body, []byte(e.marker)) {
			continue
		}
		lines = append(lines, fmt.Sprintf("  GET /%s -> 200 %s (%s)", e.name, ct, e.why))
		if sevRank(e.sev) > sevRank(sev) {
			sev = e.sev
		}
	}
	// A lone /health is a health probe, not a leak, and plenty of services
	// answer one on purpose. Anything else means management is wide open.
	if len(lines) == 0 || (len(lines) == 1 && strings.Contains(lines[0], "/health")) {
		return nil
	}
	f := t.Finding("Spring Boot 1.x actuator endpoints answered without authentication:\n" + strings.Join(lines, "\n"))
	f.Severity = sev
	return []model.Finding{f}
}

// sevRank orders severities so a check can keep the worst one it saw.
func sevRank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 5
	case model.SevHigh:
		return 4
	case model.SevMedium:
		return 3
	case model.SevLow:
		return 2
	case model.SevInfo:
		return 1
	}
	return 0
}
