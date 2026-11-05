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
		Info: checkInfo("adcs-web-enrollment", "AD CS web enrolment reachable (NTLM relay target, ESC8)", model.SevHigh,
			[]string{"http", "https"},
			"The Active Directory Certificate Services web enrolment interface answers on this host. When it accepts NTLM it is the ESC8 relay target: an attacker who can coerce any machine account to authenticate (the print spooler and EFSRPC are the usual triggers) relays that authentication here, asks for a certificate on the victim's behalf and walks away with a credential that stays valid through password changes. On an internal network this is the shortest route from a single coerced host to domain compromise, and it needs no password at any point."),
		Remediation: "Enable Extended Protection for Authentication on the /certsrv application in IIS and require HTTPS, or disable the web enrolment role if nothing uses it. Enforce LDAP signing and channel binding on the domain controllers as well, and remove the coercion triggers (disable the Print Spooler where it is not needed).",
		References: []string{
			"https://posts.specterops.io/certified-pre-owned-d95910965cd2",
			"https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview",
		},
		Applies: func(t *Target) bool {
			return webIsHTTP(t.Service) || webPortIs(t.Service, 80, 443)
		},
		Run: runADCSWebEnrollment,
	})
}

// adcsMarkers are strings the IIS enrolment application puts in its pages or
// its authentication prompt. A status code alone would match any reverse
// proxy that answers 401 for everything.
var adcsMarkers = []string{
	"Microsoft Active Directory Certificate Services",
	"Active Directory Certificate Services",
	"certsrv",
	"certrqxt.asp",
	"Microsoft Certificate Services",
}

func runADCSWebEnrollment(ctx context.Context, t *Target) []model.Finding {
	c := webClient(t)
	for _, sc := range webSchemes(t.Service) {
		if ctx.Err() != nil {
			return nil
		}
		u := webURL(t, sc, "/certsrv/")
		r, err := webDo(ctx, c, http.MethodGet, u, nil, nil)
		if err != nil {
			continue
		}
		if f := adcsFinding(ctx, t, c, sc, u, r); f != nil {
			return []model.Finding{*f}
		}
	}
	return nil
}

func adcsFinding(ctx context.Context, t *Target, c *http.Client, scheme, u string, r *webResp) *model.Finding {
	auth := strings.Join(r.Header.Values("WWW-Authenticate"), ", ")
	body := string(r.Body)
	hasMarker := false
	for _, m := range adcsMarkers {
		if strings.Contains(body, m) {
			hasMarker = true
			break
		}
	}
	// IIS answers the enrolment application with a 401 and an empty body
	// before authentication, so a marker in the body is only available on
	// anonymous installations. The 401 plus the Windows authentication
	// prompt on exactly this path is what identifies the application.
	ntlmOK := ntlmOffered(r.Header)
	// Plenty of front ends answer 401 for every unknown path, so the prompt
	// only counts when the server is also the IIS instance that AD CS runs on.
	isIIS := strings.Contains(strings.ToLower(r.Header.Get("Server")), "iis")
	switch {
	case r.Status == http.StatusUnauthorized && auth != "" && (isIIS || hasMarker):
	case r.Status == http.StatusOK && hasMarker:
	default:
		return nil
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "GET %s -> %d", u, r.Status)
	if auth != "" {
		fmt.Fprintf(&ev, "\nWWW-Authenticate: %s", printable([]byte(auth), 300))
	}
	if hasMarker {
		fmt.Fprintf(&ev, "\nPage identifies itself as AD CS web enrolment (title %q)", webTitle(r.Body))
	}
	if rr, err := webDo(ctx, c, http.MethodGet, webURL(t, scheme, "/certsrv/certfnsh.asp"), nil, nil); err == nil {
		if rr.Status == http.StatusUnauthorized || bytes.Contains(rr.Body, []byte("certrqxt")) || rr.Status == http.StatusOK {
			fmt.Fprintf(&ev, "\nGET /certsrv/certfnsh.asp -> %d (certificate request page present)", rr.Status)
		}
	}

	f := t.Finding("")
	if ntlmOK {
		ev.WriteString("\nThe endpoint offers NTLM, which is what makes it usable as an ESC8 relay target.")
		if ch, err := httpNTLMChallenge(ctx, c, u); err == nil && ntlmNamesKnown(ch) {
			fmt.Fprintf(&ev, "\nThe NTLM CHALLENGE identifies the CA host:\n%s", ntlmChallengeEvidence(ch))
		}
		if scheme == "http" {
			ev.WriteString("\nServed over plain HTTP, so channel binding cannot protect the relay at all.")
		}
	} else {
		// Without NTLM the relay path is closed, but an enrolment interface
		// reachable from a user VLAN is still an exposure worth raising.
		ev.WriteString("\nNTLM is not offered on this endpoint, so the ESC8 relay path is not open here; the enrolment interface is still reachable from this network.")
		f.Severity = model.SevMedium
		f.Title = "AD CS web enrolment reachable from this network"
	}
	f.Evidence = truncate(ev.String(), 4000)
	return &f
}
