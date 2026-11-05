package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("printer-unauth-admin", "Printer administration interface reachable without authentication", model.SevMedium,
			[]string{"http", "https", "printer"},
			"A printer or multifunction device exposes its administration pages without asking for a password. Printers are the quietest credential store on an internal network: to scan to a share and to look names up they are given an SMB account and an LDAP bind account, and both sit in the address book and the network configuration pages that this interface serves. Some models show the LDAP bind password back in the page source; the ones that do not will still happily be pointed at an attacker-controlled server and made to authenticate to it (the pass-back attack), which hands over the same credential. The accounts involved are rarely low privileged and almost never rotated."),
		Remediation: "Set an administrator password on the device and enable its authentication for the web interface, then move the management interfaces onto a dedicated VLAN that user networks cannot reach. Give the scan-to-folder and LDAP lookup functions their own least-privileged accounts, and disable any unused protocol (FTP, Telnet, raw 9100) on the device.",
		References: []string{
			"https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		Applies: printerApplies,
		Run:     runPrinterUnauthAdmin,
	})
}

// printerVendorMarkers are the strings device web servers put in their Server header,
// their page titles or their fingerprint. A device has to match one of these before any
// page is requested.
var printerVendorMarkers = []string{
	"hp http server", "hp officejet", "hp laserjet", "hp color laserjet",
	"xerox", "workcentre", "versalink", "altalink",
	"ricoh", "savin", "lanier",
	"brother", "konica minolta", "bizhub",
	"kyocera", "lexmark", "sharp mx", "toshiba tec", "oki ",
	"canon", "imagerunner", "epson", "jetdirect", "printer", "embedded web server",
}

// printerAdminPages are the administration entry points per vendor, with the content that
// proves the page really is the device's own.
var printerAdminPages = []struct {
	path    string
	markers []string
}{
	{"/hp/device/DeviceStatus/Index", []string{"DeviceStatus", "Device Status"}},
	{"/hp/device/InternalPages/Index", []string{"Information Pages", "InternalPages"}},
	{"/DevMgmt/ProductConfigDyn.xml", []string{"ProductConfigDyn", "MakeAndModel"}},
	{"/properties/", []string{"Properties", "Xerox"}},
	{"/web/guest/en/websys/webArch/mainFrame.cgi", []string{"Web Image Monitor", "webArch"}},
	{"/general/status.html", []string{"Brother", "Device Status"}},
	{"/startwlm/Start_Wlm.htm", []string{"KYOCERA", "Command Center"}},
	{"/cgi-bin/dynamic/printer/config/reports/deviceinfo.html", []string{"Device Information", "Lexmark"}},
	{"/sws/app/information/home/home.html", []string{"Samsung", "SyncThru"}},
	{"/wcd/system_counter.xml", []string{"system_counter", "KONICA"}},
}

// printerLoginMarkers are the signs that the page served is in fact a login prompt.
// Several devices answer 200 with a sign-in form, which is the opposite of the finding.
var printerLoginMarkers = []string{
	"type=\"password\"", "type='password'", "signin", "sign in", "login",
	"ログイン", "password required",
}

func printerApplies(t *Target) bool {
	s := t.Service
	if !webIsHTTP(s) && !webPortIs(s, 80, 443, 280, 631, 8000, 8080) {
		return false
	}
	fp := webFingerprintText(s)
	for _, m := range printerVendorMarkers {
		if strings.Contains(fp, m) {
			return true
		}
	}
	// The raw print port is the other reliable sign that the host is a printer, even when
	// its web server says nothing useful about itself.
	return t.HasPort(9100, model.TCP) && (webIsHTTP(s) || webPortIs(s, 80, 443))
}

func runPrinterUnauthAdmin(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	for _, sc := range webSchemes(t.Service) {
		if ctx.Err() != nil {
			return nil
		}
		for _, p := range printerAdminPages {
			if ctx.Err() != nil {
				return nil
			}
			u := webURL(t, sc, p.path)
			r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
			if err != nil {
				// A device that refuses the whole scheme will refuse every path on it;
				// move on rather than hammering it.
				break
			}
			if r.Status != http.StatusOK || !printerBodyMatches(r.Body, p.markers) {
				continue
			}
			if printerIsLoginPage(r.Body) {
				t.Log.Debug("printer admin page is a login prompt", "url", u)
				continue
			}
			ev := fmt.Sprintf("GET %s -> 200 without any credential.\n", u)
			if ttl := webTitle(r.Body); ttl != "" {
				ev += fmt.Sprintf("  page title    %s\n", ttl)
			}
			if sv := r.Header.Get("Server"); sv != "" {
				ev += fmt.Sprintf("  Server        %s\n", printable([]byte(sv), 120))
			}
			ev += fmt.Sprintf("  confirmed by  %q in the response body\n", printerFirstMatch(r.Body, p.markers))
			if t.HasPort(9100, model.TCP) {
				ev += "  raw print port 9100/tcp is also open on this host\n"
			}
			ev += "Only this page was read. The address book and the network configuration pages behind it were not opened."
			return []model.Finding{t.Finding(strings.TrimRight(ev, "\n"))}
		}
	}
	return nil
}

func printerBodyMatches(body []byte, markers []string) bool {
	return printerFirstMatch(body, markers) != ""
}

func printerFirstMatch(body []byte, markers []string) string {
	s := string(body)
	for _, m := range markers {
		if strings.Contains(s, m) {
			return m
		}
	}
	return ""
}

func printerIsLoginPage(body []byte) bool {
	s := strings.ToLower(string(body))
	for _, m := range printerLoginMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
