package fingerprint

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
)

// techRule is a lightweight technology signature. A rule matches when any of
// its non-empty conditions matches (OR semantics).
type techRule struct {
	name   string
	header map[string]*regexp.Regexp // canonical header name -> regexp on value
	cookie []string                  // cookie name prefixes (case-insensitive)
	body   []string                  // case-sensitive substrings of the body
	bodyRe *regexp.Regexp
	title  *regexp.Regexp
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var techRules = []techRule{
	// Web servers / frameworks
	{name: "Microsoft IIS", header: map[string]*regexp.Regexp{"Server": re(`(?i)Microsoft-IIS`)}},
	{name: "ASP.NET", header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)ASP\.NET`), "X-Aspnet-Version": re(`.`), "X-Aspnetmvc-Version": re(`.`)}, cookie: []string{"asp.net_sessionid", ".aspxauth"}, body: []string{"__VIEWSTATE"}},
	{name: "Apache HTTP Server", header: map[string]*regexp.Regexp{"Server": re(`(?i)^Apache(/|$| )`)}},
	{name: "nginx", header: map[string]*regexp.Regexp{"Server": re(`(?i)^nginx`)}},
	{name: "OpenResty", header: map[string]*regexp.Regexp{"Server": re(`(?i)openresty`)}},
	{name: "lighttpd", header: map[string]*regexp.Regexp{"Server": re(`(?i)lighttpd`)}},
	{name: "Apache Tomcat", header: map[string]*regexp.Regexp{"Server": re(`(?i)Apache-Coyote|Tomcat`)}, title: re(`(?i)Apache Tomcat`), body: []string{"Apache Tomcat", "/manager/html"}},
	{name: "Jetty", header: map[string]*regexp.Regexp{"Server": re(`(?i)Jetty`)}},
	{name: "PHP", header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)PHP`)}, cookie: []string{"phpsessid"}},
	{name: "Java", cookie: []string{"jsessionid"}, header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)Servlet|JSP`)}},
	{name: "Express", header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)Express`)}},
	{name: "Django", cookie: []string{"csrftoken", "django"}, body: []string{"csrfmiddlewaretoken"}},
	{name: "Laravel", cookie: []string{"laravel_session", "xsrf-token"}},
	{name: "Ruby on Rails", header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)Phusion Passenger`)}, cookie: []string{"_rails"}},
	{name: "Spring Boot", body: []string{"Whitelabel Error Page"}},
	{name: "Oracle WebLogic", header: map[string]*regexp.Regexp{"Server": re(`(?i)WebLogic`)}, body: []string{"WebLogic Server"}},
	{name: "JBoss / WildFly", header: map[string]*regexp.Regexp{"X-Powered-By": re(`(?i)JBoss|Undertow|WildFly`), "Server": re(`(?i)JBoss|WildFly`)}, title: re(`(?i)WildFly|JBoss`)},
	{name: "IBM WebSphere", header: map[string]*regexp.Regexp{"Server": re(`(?i)WebSphere`)}, body: []string{"WebSphere"}},
	// DevOps / apps
	{name: "Jenkins", header: map[string]*regexp.Regexp{"X-Jenkins": re(`.`), "X-Hudson": re(`.`)}, title: re(`(?i)Jenkins`), body: []string{"/static/jenkins", "jenkins-head"}},
	{name: "GitLab", cookie: []string{"_gitlab_session"}, title: re(`(?i)GitLab`), body: []string{"gitlab-logo", "content=\"GitLab"}},
	{name: "Gitea", cookie: []string{"i_like_gitea"}, title: re(`(?i)Gitea`)},
	{name: "Bitbucket", title: re(`(?i)Bitbucket`)},
	{name: "Atlassian Confluence", header: map[string]*regexp.Regexp{"X-Confluence-Request-Time": re(`.`)}, title: re(`(?i)Confluence`), body: []string{"confluence-base-url"}},
	{name: "Atlassian Jira", header: map[string]*regexp.Regexp{"X-Arequestid": re(`.`)}, cookie: []string{"atlassian.xsrf.token"}, title: re(`(?i)\bJira\b`)},
	{name: "SonarQube", title: re(`(?i)SonarQube`)},
	{name: "Nexus Repository", title: re(`(?i)Nexus Repository`), header: map[string]*regexp.Regexp{"Server": re(`(?i)Nexus`)}},
	{name: "Artifactory", title: re(`(?i)Artifactory`), header: map[string]*regexp.Regexp{"X-Artifactory-Id": re(`.`)}},
	{name: "Grafana", cookie: []string{"grafana_session"}, title: re(`(?i)^Grafana`), body: []string{"grafana-app", "window.grafanaBootData"}},
	{name: "Kibana", header: map[string]*regexp.Regexp{"Kbn-Name": re(`.`), "Kbn-Version": re(`.`)}, title: re(`(?i)Kibana|Elastic`)},
	{name: "Elasticsearch", body: []string{"\"cluster_name\"", "You Know, for Search"}},
	{name: "Prometheus", title: re(`(?i)Prometheus`)},
	{name: "RabbitMQ Management", title: re(`(?i)RabbitMQ Management`)},
	{name: "Portainer", title: re(`(?i)Portainer`)},
	{name: "Kubernetes API", body: []string{"\"kind\":\"Status\"", "\"apiVersion\":\"v1\""}},
	{name: "Docker Registry", header: map[string]*regexp.Regexp{"Docker-Distribution-Api-Version": re(`.`)}},
	{name: "Zabbix", title: re(`(?i)Zabbix`), cookie: []string{"zbx_session"}},
	{name: "Nagios", title: re(`(?i)Nagios`), header: map[string]*regexp.Regexp{"Www-Authenticate": re(`(?i)Nagios`)}},
	{name: "phpMyAdmin", title: re(`(?i)phpMyAdmin`), cookie: []string{"phpmyadmin", "pma_"}},
	{name: "Adminer", title: re(`(?i)Adminer`)},
	{name: "Webmin", title: re(`(?i)Webmin`), header: map[string]*regexp.Regexp{"Server": re(`(?i)MiniServ`)}},
	{name: "pfSense", title: re(`(?i)pfSense`)},
	{name: "OPNsense", title: re(`(?i)OPNsense`)},
	{name: "Roundcube", title: re(`(?i)Roundcube`), cookie: []string{"roundcube_sessid"}},
	{name: "Keycloak", title: re(`(?i)Keycloak`), body: []string{"/auth/resources/", "keycloak"}},
	{name: "MinIO", header: map[string]*regexp.Regexp{"Server": re(`(?i)MinIO`)}},
	{name: "HashiCorp Vault", title: re(`(?i)^Vault$`), header: map[string]*regexp.Regexp{"Server": re(`(?i)Vault`)}},
	{name: "Splunk", header: map[string]*regexp.Regexp{"Server": re(`(?i)Splunkd`)}, title: re(`(?i)Splunk`)},
	// CMS
	{name: "WordPress", body: []string{"/wp-content/", "/wp-includes/"}, header: map[string]*regexp.Regexp{"Link": re(`wp-json`)}},
	{name: "Drupal", header: map[string]*regexp.Regexp{"X-Drupal-Cache": re(`.`), "X-Generator": re(`(?i)Drupal`)}, body: []string{"Drupal.settings", "/sites/default/files"}},
	{name: "Joomla", body: []string{"/media/jui/", "content=\"Joomla"}},
	{name: "SharePoint", header: map[string]*regexp.Regexp{"Microsoftsharepointteamservices": re(`.`), "Sprequestguid": re(`.`)}, title: re(`(?i)SharePoint`)},
	// Microsoft
	{name: "Outlook Web App", title: re(`(?i)Outlook`), body: []string{"/owa/auth/", "OwaPage"}, header: map[string]*regexp.Regexp{"X-Owa-Version": re(`.`)}},
	{name: "Microsoft Exchange", header: map[string]*regexp.Regexp{"X-Feserver": re(`.`), "X-Owa-Version": re(`.`), "X-Calculatedbetarget": re(`.`)}, body: []string{"/ecp/", "Exchange Server"}},
	{name: "ADFS", title: re(`(?i)\bAD FS\b`), body: []string{"/adfs/ls/", "adfs/portal"}},
	{name: "Windows RD Web Access", body: []string{"/RDWeb/", "TSWAFeatureCheck"}, title: re(`(?i)RD Web Access`)},
	{name: "WSUS", body: []string{"SimpleAuthWebService"}},
	{name: "SCCM", body: []string{"/CCM_System", "SMS_MP"}},
	// Virtualisation / BMC
	{name: "VMware vCenter", title: re(`(?i)vSphere|vCenter`), body: []string{"/vsphere-client/", "VMware vCenter", "vmware-vcenter"}},
	{name: "VMware ESXi", title: re(`(?i)VMware ESXi`), body: []string{"VMware ESXi", "/ui/#/host", "esxUiApp"}},
	{name: "VMware Horizon", title: re(`(?i)VMware Horizon`)},
	{name: "Proxmox VE", title: re(`(?i)Proxmox`), header: map[string]*regexp.Regexp{"Server": re(`(?i)pve-api-daemon`)}},
	{name: "HPE iLO", title: re(`(?i)iLO|Integrated Lights-Out`), header: map[string]*regexp.Regexp{"Server": re(`(?i)HP-iLO`)}, body: []string{"Integrated Lights-Out", "ilo.js"}},
	{name: "Dell iDRAC", title: re(`(?i)iDRAC|Integrated Dell Remote Access`), body: []string{"idrac", "iDRAC"}},
	{name: "Supermicro IPMI", title: re(`(?i)Supermicro`), body: []string{"ATEN International"}},
	{name: "Lenovo XClarity", title: re(`(?i)XClarity`)},
	{name: "Cisco UCS", title: re(`(?i)Cisco UCS`)},
	{name: "Nutanix Prism", title: re(`(?i)Nutanix`)},
	// Network / security appliances
	{name: "Fortinet FortiGate", title: re(`(?i)FortiGate|Fortinet`), body: []string{"/remote/login", "fortinet", "ftnt-fortinet"}, cookie: []string{"svpncookie", "ccsrftoken"}, header: map[string]*regexp.Regexp{"Server": re(`(?i)xxxxxxxx-xxxxx`)}},
	{name: "Palo Alto GlobalProtect", title: re(`(?i)GlobalProtect`), body: []string{"global-protect", "/php/login.php"}},
	{name: "Citrix NetScaler / ADC", cookie: []string{"nsc_", "citrix_ns_id"}, title: re(`(?i)Citrix Gateway|NetScaler`), body: []string{"/vpn/index.html", "/logon/LogonPoint/"}},
	{name: "Citrix StoreFront", body: []string{"/Citrix/StoreWeb", "CitrixReceiver"}},
	{name: "Pulse Secure / Ivanti", body: []string{"/dana-na/", "dana-cached"}, cookie: []string{"dssignin"}},
	{name: "Cisco ASA / AnyConnect", body: []string{"/+CSCOE+/", "webvpn"}, cookie: []string{"webvpn"}},
	{name: "Cisco IOS", header: map[string]*regexp.Regexp{"Server": re(`(?i)cisco-IOS`)}},
	{name: "SonicWall", title: re(`(?i)SonicWall`), header: map[string]*regexp.Regexp{"Server": re(`(?i)SonicWALL`)}},
	{name: "Check Point", title: re(`(?i)Check Point|Gaia`)},
	{name: "Sophos", title: re(`(?i)Sophos`)},
	{name: "F5 BIG-IP", cookie: []string{"bigipserver", "f5_", "mrhsession"}, title: re(`(?i)BIG-IP`), header: map[string]*regexp.Regexp{"Server": re(`(?i)BigIP|BIG-IP`)}},
	{name: "MikroTik RouterOS", title: re(`(?i)RouterOS|mikrotik`)},
	{name: "Ubiquiti UniFi", title: re(`(?i)UniFi`)},
	{name: "Synology DSM", title: re(`(?i)Synology|DiskStation`)},
	{name: "QNAP", title: re(`(?i)QNAP|QTS`)},
	// Printers / IoT
	{name: "HP Printer", title: re(`(?i)HP (LaserJet|Color LaserJet|OfficeJet|PageWide|DesignJet)`), header: map[string]*regexp.Regexp{"Server": re(`(?i)HP HTTP Server|HP-ChaiSOE`)}},
	{name: "Canon Printer", title: re(`(?i)Canon|Remote UI`), header: map[string]*regexp.Regexp{"Server": re(`(?i)CANON HTTP Server`)}},
	{name: "Xerox Printer", title: re(`(?i)Xerox|CentreWare`)},
	{name: "Ricoh Printer", title: re(`(?i)Web Image Monitor|RICOH`)},
	{name: "Brother Printer", header: map[string]*regexp.Regexp{"Server": re(`(?i)debut`)}, title: re(`(?i)Brother`)},
	{name: "Kyocera Printer", title: re(`(?i)Kyocera|Command Center`)},
	{name: "Lexmark Printer", title: re(`(?i)Lexmark`)},
	{name: "Konica Minolta Printer", title: re(`(?i)PageScope|Konica`)},
	{name: "Epson Printer", title: re(`(?i)EPSON`)},
	{name: "Axis Camera", title: re(`(?i)AXIS`), body: []string{"/axis-cgi/"}},
	{name: "Hikvision", body: []string{"/doc/page/login.asp"}, header: map[string]*regexp.Regexp{"Server": re(`(?i)DNVRS-Webs|App-webs|Hikvision`)}},
	{name: "Dahua", body: []string{"/RPC2_Login"}},
	{name: "APC UPS", title: re(`(?i)APC|Network Management Card`)},
}

// detectTech returns the technologies recognised from the response.
func detectTech(h http.Header, body []byte, title string) []string {
	cookieNames := make([]string, 0, 4)
	for _, c := range h.Values("Set-Cookie") {
		n, _, _ := strings.Cut(c, "=")
		cookieNames = append(cookieNames, strings.ToLower(strings.TrimSpace(n)))
	}
	var out []string
	for i := range techRules {
		r := &techRules[i]
		if techMatch(r, h, body, title, cookieNames) {
			out = append(out, r.name)
		}
	}
	return out
}

func techMatch(r *techRule, h http.Header, body []byte, title string, cookies []string) bool {
	for name, rx := range r.header {
		for _, v := range h.Values(name) {
			if rx.MatchString(v) {
				return true
			}
		}
	}
	for _, prefix := range r.cookie {
		for _, c := range cookies {
			if strings.HasPrefix(c, prefix) {
				return true
			}
		}
	}
	for _, s := range r.body {
		if bytes.Contains(body, []byte(s)) {
			return true
		}
	}
	if r.bodyRe != nil && r.bodyRe.Match(body) {
		return true
	}
	return r.title != nil && title != "" && r.title.MatchString(title)
}
