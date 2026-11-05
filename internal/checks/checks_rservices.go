package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("rservices-exposed", "Berkeley r-services exposed (rlogin/rsh/rexec)", model.SevMedium,
			[]string{"exec", "login", "shell", "rlogin", "rsh", "rexec", "kshell", "klogin"},
			"The host exposes one of the Berkeley remote services: rexec (512), rlogin (513) or rsh (514). They carry credentials and session data in cleartext and authenticate with host-based trust (~/.rhosts, /etc/hosts.equiv), which an attacker on the same network can forge by spoofing the source address once the trusted host is known. Credentials and commands are readable by anyone able to capture traffic."),
		Remediation: "Disable rexec, rlogin and rsh (remove the inetd/xinetd entries or the rsh-server package) and use SSH with public-key authentication instead. Delete any remaining .rhosts and /etc/hosts.equiv files.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/319.html",
			"https://www.rfc-editor.org/rfc/rfc1282",
		},
		Applies: rservicesApplies,
		Run:     runRServices,
	})
}

// rservicePorts maps the port to the protocol name as reported.
var rservicePorts = map[int]string{
	512: "rexec",
	513: "rlogin",
	514: "rsh",
	543: "klogin (Kerberos rlogin)",
	544: "kshell (Kerberos rsh)",
}

func rservicesApplies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP {
		return false
	}
	if _, ok := rservicePorts[s.Port]; ok {
		// Port 514/udp is syslog; 514/tcp with a "syslog" name is rsyslog.
		if strings.Contains(svcLower(s), "syslog") {
			return false
		}
		return true
	}
	switch svcLower(s) {
	case "rlogin", "rsh", "rexec", "exec", "login", "shell", "kshell", "klogin":
		return true
	}
	return false
}

func svcLower(s model.Service) string { return strings.ToLower(strings.TrimSpace(s.Name)) }

// runRServices reports the exposure. The r-services protocols start with the client
// sending its credentials, so there is no banner to read and no way to probe them further
// without attempting a login: NETY reports the exposure from the open port alone and
// never authenticates.
func runRServices(_ context.Context, t *Target) []model.Finding {
	name := rservicePorts[t.Service.Port]
	if name == "" {
		name = svcLower(t.Service)
	}
	ev := fmt.Sprintf("%s reachable on %s/tcp", name, strconv.Itoa(t.Service.Port))
	if b := strings.TrimSpace(t.Service.Banner); b != "" {
		ev += fmt.Sprintf(" (banner: %q)", truncate(b, 200))
	}
	if p := strings.TrimSpace(t.Service.Product); p != "" {
		ev += fmt.Sprintf(" (product: %s %s)", p, t.Service.Version)
	}
	ev += "\nNo login was attempted: the r-services have no pre-authentication handshake to probe."
	return []model.Finding{t.Finding(ev)}
}
