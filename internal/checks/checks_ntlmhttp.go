package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ntlm-info-disclosure", "HTTP endpoint discloses Windows domain and host names over NTLM", model.SevInfo,
			[]string{"http", "https"},
			"The web server offers NTLM authentication, and the CHALLENGE message it returns before any credential is sent carries the host's NetBIOS name, its DNS name, the Active Directory domain name and the Windows version. None of that is secret on its own, but it is exactly what an attacker needs to go from an IP address to a domain: the AD domain name, the naming convention of the estate and the patch level of the host, obtained without authenticating."),
		Remediation: "Prefer Kerberos (Negotiate) and disable the NTLM fallback on internet-facing and user-facing endpoints where it is not required. The disclosure cannot be switched off while NTLM is offered, so the practical control is to stop offering NTLM and to restrict which networks reach the endpoint at all.",
		References: []string{
			"https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
		Applies: func(t *Target) bool {
			return webIsHTTP(t.Service) || webPortIs(t.Service, 80, 443, 5985, 5986, 593)
		},
		Run: runNTLMInfo,
	})
	register(&Check{
		Info: checkInfo("winrm-exposed", "WinRM remote management service reachable", model.SevInfo,
			[]string{"wsman", "http", "https"},
			"Windows Remote Management answers on this host. WinRM is a remote command execution service: any account that is a local administrator (or a member of Remote Management Users) can run commands on the host through it, and it is the usual landing point once credentials are captured or relayed on an internal network. Reaching it from a user VLAN is a segmentation question rather than a vulnerability, which is why this is reported for information."),
		Remediation: "Restrict WinRM to the administration network with the Windows firewall rule scope or an IPsec policy, prefer HTTPS (5986) so credentials are not protected by NTLM alone, and keep the Remote Management Users group small.",
		References: []string{
			"https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management",
			"https://attack.mitre.org/techniques/T1021/006/",
		},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"wsman", "wsmans"}, 5985, 5986)
		},
		Run: runWinRMExposed,
	})
}

// ntlmProbePaths are the endpoints that commonly answer with NTLM on a Windows estate.
// The list is short on purpose: the point is one CHALLENGE, not a directory enumeration.
var ntlmProbePaths = []string{"/", "/wsman", "/rpc/rpcproxy.dll", "/ews/Exchange.asmx", "/owa/", "/certsrv/"}

// httpNTLMChallenge sends an NTLM NEGOTIATE (type 1) message to url and decodes the
// CHALLENGE (type 2) the server answers with. No credential is ever sent: the exchange
// stops before the AUTHENTICATE message, so no logon is attempted and nothing is recorded
// as a failed sign-in.
func httpNTLMChallenge(ctx context.Context, c *http.Client, url string) (*ntlm.Challenge, error) {
	r, err := webDo(ctx, c, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusUnauthorized || !ntlmOffered(r.Header) {
		return nil, fmt.Errorf("ntlm: %s does not offer NTLM (status %d)", url, r.Status)
	}
	neg := base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())
	rr, err := webDo(ctx, c, http.MethodGet, url, nil, map[string]string{"Authorization": "NTLM " + neg})
	if err != nil {
		return nil, err
	}
	for _, v := range rr.Header.Values("WWW-Authenticate") {
		f := strings.Fields(v)
		if len(f) != 2 || !strings.EqualFold(f[0], "NTLM") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			continue
		}
		return ntlm.FindChallenge(raw)
	}
	return nil, fmt.Errorf("ntlm: %s returned no CHALLENGE", url)
}

// ntlmOffered reports whether the response offers NTLM directly. Negotiate is
// deliberately not treated as NTLM here: a Negotiate-only endpoint may be Kerberos only,
// and guessing would put a wrong fact in a client report.
func ntlmOffered(h http.Header) bool {
	for _, v := range h.Values("WWW-Authenticate") {
		for _, scheme := range strings.Split(v, ",") {
			name, _, _ := strings.Cut(strings.TrimSpace(scheme), " ")
			if strings.EqualFold(name, "NTLM") {
				return true
			}
		}
	}
	return false
}

// ntlmChallengeEvidence renders the names a CHALLENGE disclosed.
func ntlmChallengeEvidence(ch *ntlm.Challenge) string {
	var lines []string
	for _, f := range []struct{ k, v string }{
		{"NetBIOS domain", ch.NetBIOSDomain},
		{"NetBIOS computer", ch.NetBIOSComputer},
		{"DNS domain", ch.DNSDomain},
		{"DNS computer", ch.DNSComputer},
		{"DNS forest", ch.DNSTree},
		{"target name", ch.TargetName},
	} {
		if f.v != "" {
			lines = append(lines, fmt.Sprintf("  %-17s %s", f.k, truncate(f.v, 255)))
		}
	}
	if ch.Version != nil {
		name, _ := ch.Version.Product()
		lines = append(lines, fmt.Sprintf("  %-17s %s (%s)", "Windows version", ch.Version.String(), name))
	}
	return strings.Join(lines, "\n")
}

// ntlmNamesKnown reports whether a CHALLENGE actually disclosed identity information. A
// challenge with no AV pairs is not a finding.
func ntlmNamesKnown(ch *ntlm.Challenge) bool {
	return ch != nil && (ch.NetBIOSDomain != "" || ch.NetBIOSComputer != "" || ch.DNSDomain != "" || ch.DNSComputer != "")
}

func runNTLMInfo(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	schemes := webSchemes(t.Service)
	for _, p := range ntlmProbePaths {
		if ctx.Err() != nil {
			return nil
		}
		for _, sc := range schemes {
			ch, err := httpNTLMChallenge(ctx, c, webURL(t, sc, p))
			if err != nil {
				t.Log.Debug("ntlm challenge", "path", p, "err", err)
				continue
			}
			if !ntlmNamesKnown(ch) {
				continue
			}
			ev := fmt.Sprintf("GET %s with an NTLM NEGOTIATE message returned a CHALLENGE that discloses:\n%s\nNo credential was sent: the exchange stopped before the AUTHENTICATE message.",
				webURL(t, sc, p), ntlmChallengeEvidence(ch))
			return []model.Finding{t.Finding(ev)}
		}
	}
	return nil
}

func runWinRMExposed(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	// WinRM answers on /wsman only. A GET is refused (it wants POST), and the refusal is
	// exactly what identifies the service: Microsoft's HTTP server stack with a
	// WS-Management endpoint behind it.
	r, sc, err := webGetFirst(ctx, t, c, "/wsman", nil)
	if err != nil {
		return nil
	}
	server := r.Header.Get("Server")
	isHTTPAPI := strings.Contains(strings.ToLower(server), "microsoft-httpapi")
	auth := strings.Join(r.Header.Values("WWW-Authenticate"), ", ")
	switch {
	case r.Status == http.StatusUnauthorized && auth != "":
	case r.Status == http.StatusMethodNotAllowed && isHTTPAPI:
	case r.Status == http.StatusNotImplemented && isHTTPAPI:
	default:
		return nil
	}
	var ev strings.Builder
	fmt.Fprintf(&ev, "GET %s -> %d", webURL(t, sc, "/wsman"), r.Status)
	if server != "" {
		fmt.Fprintf(&ev, ", Server: %s", printable([]byte(server), 120))
	}
	if auth != "" {
		fmt.Fprintf(&ev, "\nWWW-Authenticate: %s", printable([]byte(auth), 300))
	}
	if sc == "http" {
		ev.WriteString("\nListening on plain HTTP (5985): the WS-Management payload is protected by the NTLM/Kerberos session key only, not by TLS.")
	}
	return []model.Finding{t.Finding(ev.String())}
}
