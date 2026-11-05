package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("snmp-write-community", "SNMP answers to a community string conventionally used for write access", model.SevMedium,
			[]string{"snmp"},
			"The SNMP agent answers requests authenticated by a community string that is conventionally configured read-write. A community string is a cleartext password with no account behind it, so if this one carries write access anyone on the network can reconfigure the device, and on network equipment that includes making it upload its running configuration or load a new image. NETY only read with this string: it issued a GET and never a SET, so write access is indicated by the convention and by the fact that the string is configured at all, and has not been confirmed."),
		Remediation: "Remove the community string, or if the device genuinely needs SNMP write, replace it with a long random value and restrict it with an agent ACL to the management stations that use it. Better, move to SNMPv3 with authPriv and drop v1/v2c entirely. Confirm on the device whether this string is configured RO or RW: the scan deliberately did not.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/1188.html",
			"https://datatracker.ietf.org/doc/html/rfc3414",
		},
		Applies: snmpApplies,
		Run:     runSNMPWriteCommunity,
	})
}

// snmpWriteCommunities are the strings vendors and runbooks use when they want a
// read-write community. "private" is not in the list on purpose: snmp-default-community
// already tries it and already raises it as a read-write finding, and repeating it here
// would report the same string twice in one report. The list stays this small
// deliberately; it is not a wordlist and turning it into one would be credential
// guessing.
var snmpWriteCommunities = []string{"write", "manager"}

// runSNMPWriteCommunity issues a GET of the system group with each candidate. No SET is
// ever sent, so nothing on the device is changed and the check cannot be the reason a
// device's configuration moves.
func runSNMPWriteCommunity(ctx context.Context, t *Target) []model.Finding {
	var lines []string
	for _, comm := range snmpWriteCommunities {
		if ctx.Err() != nil {
			break
		}
		hit, err := snmpTryCommunity(ctx, t, comm)
		if err != nil {
			t.Log.Debug("snmp write community rejected", "community", comm, "err", err)
			continue
		}
		line := fmt.Sprintf("community %q accepted for a GET over %s", hit.community, hit.version)
		if hit.sysName != "" {
			line += fmt.Sprintf(", sysName=%q", hit.sysName)
		}
		if hit.sysDescr != "" {
			line += fmt.Sprintf(", sysDescr=%q", truncate(hit.sysDescr, 200))
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil
	}
	ev := strings.Join(lines, "\n") +
		"\nOnly GET requests were sent. No SET was attempted, so whether this string also carries write access was not tested and has to be read from the device configuration."
	return []model.Finding{t.Finding(ev)}
}
