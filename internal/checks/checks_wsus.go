package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("wsus-over-http", "WSUS update service served over plain HTTP", model.SevHigh,
			[]string{"http", "wsus"},
			"A Windows Server Update Services endpoint answers over cleartext HTTP. Clients fetch the update metadata over this channel, so an attacker in a man-in-the-middle position on the network can rewrite it and have every workstation install an attacker-chosen package as SYSTEM. The update binaries are still Microsoft-signed, but the metadata chooses which signed binary runs and with which command line, which is enough (the WSUSpect / PyWSUS technique). On a flat internal network, ARP or DHCP spoofing is all it takes to reach that position."),
		Remediation: "Serve WSUS over HTTPS only: bind a certificate to port 8531, run 'wsusutil configuressl <fqdn>' and point clients at https:// through the WUServer policy, then block plain 8530 from client networks. Make sure the clients trust the certificate so they cannot silently fall back.",
		References: []string{
			"https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus",
			"https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update-wp.pdf",
		},
		Applies: wsusApplies,
		Run:     runWSUSOverHTTP,
	})
}

func wsusApplies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP {
		return false
	}
	// 8531 is the TLS port: a WSUS that answers there is configured the way
	// it should be, so only the cleartext side is worth probing.
	if isTLS(s) || s.Port == 8531 || s.Port == 443 {
		return false
	}
	return webPortIs(s, 8530) || (webIsHTTP(s) && strings.Contains(webFingerprintText(s), "wsus"))
}

// wsusPaths are the virtual directories the WSUS server role publishes.
var wsusPaths = []struct {
	path   string
	marker string
}{
	{"/ClientWebService/client.asmx", "ClientWebService"},
	{"/SimpleAuthWebService/SimpleAuth.asmx", "SimpleAuth"},
	{"/ReportingWebService/ReportingWebService.asmx", "ReportingWebService"},
}

func runWSUSOverHTTP(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	var hits []string
	for _, p := range wsusPaths {
		if ctx.Err() != nil {
			break
		}
		r, err := webDo(ctx, c, http.MethodGet, webURL(t, "http", p.path), nil, nil)
		if err != nil || r.Status != http.StatusOK {
			continue
		}
		// An .asmx endpoint answers a plain GET with its service description
		// page. Confirming on the body keeps a catch-all 200 from counting.
		if !bytes.Contains(r.Body, []byte(p.marker)) {
			continue
		}
		if !bytes.Contains(r.Body, []byte("Web Service")) && !bytes.Contains(r.Body, []byte("soap:address")) && !bytes.Contains(r.Body, []byte("SOAP")) {
			continue
		}
		hits = append(hits, fmt.Sprintf("  GET http://%s%s -> 200, %q (title %q)", t.Addr(), p.path, p.marker, webTitle(r.Body)))
	}
	if len(hits) == 0 {
		return nil
	}
	var ev strings.Builder
	ev.WriteString("WSUS virtual directories answered over cleartext HTTP:\n")
	ev.WriteString(strings.Join(hits, "\n"))
	if t.HasPort(8531, model.TCP) {
		ev.WriteString("\nPort 8531 is also open on this host, so TLS is configured but the cleartext port is still reachable from this network.")
	} else {
		ev.WriteString("\nNo WSUS TLS port (8531) is open on this host: clients have no encrypted alternative.")
	}
	return []model.Finding{t.Finding(ev.String())}
}
