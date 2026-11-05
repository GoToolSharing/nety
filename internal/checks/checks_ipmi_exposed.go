package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ipmi-exposed", "IPMI / BMC management interface reachable", model.SevMedium,
			[]string{"asf-rmcp", "ipmi", "rmcp"},
			"A baseboard management controller answers IPMI-over-LAN on UDP 623 from this network. A BMC is an independent computer with full out-of-band control of the host: power, console, virtual media and often the host's disks. BMC firmware is rarely patched and the IPMI protocol itself has unfixable design flaws, so reaching one from a user or server VLAN is a serious segmentation problem regardless of its configuration."),
		Remediation: "Move every BMC to a dedicated, strictly filtered management VLAN that no user network can route to. Disable IPMI-over-LAN where the vendor offers a Redfish-only mode, keep BMC firmware current, and remove the vendor's default accounts.",
		References: []string{
			"https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/",
			"https://csrc.nist.gov/pubs/sp/800/147/b/final",
		},
		Applies: ipmiApplies,
		Run:     runIPMIExposed,
	})
}

// runIPMIExposed confirms a live BMC with a single read-only "Get Channel Authentication
// Capabilities" request. No session is opened and no credential is sent.
func runIPMIExposed(ctx context.Context, t *Target) []model.Finding {
	c, err := t.DialUDP(ctx, t.Service.Port)
	if err != nil {
		return nil
	}
	defer c.Close()

	reply, err := ipmiExchange(c, ipmiTimeout(t), ipmiGetChannelAuthCaps,
		func(b []byte) bool { return len(b) >= 21 && b[19] == 0x38 })
	if err != nil {
		t.Log.Debug("ipmi get channel auth caps failed", "err", err)
		return nil
	}
	v2, err := ipmiAuthCaps(reply)
	if err != nil {
		t.Log.Debug("ipmi auth caps malformed", "err", err)
		return nil
	}

	details := []string{fmt.Sprintf("BMC answered Get Channel Authentication Capabilities on %d/udp", t.Service.Port)}
	if v2 {
		details = append(details, "IPMI 2.0 (RMCP+) supported")
	} else {
		details = append(details, "IPMI 1.5 only")
	}
	// Byte 23 of the reply carries the v1.5 authentication type support bits and byte 24
	// the "null user"/"anonymous login" status bits.
	if len(reply) >= 25 {
		if types := ipmiAuthTypeNames(reply[21]); len(types) > 0 {
			details = append(details, "authentication types offered: "+strings.Join(types, ", "))
		}
		if reply[23]&0x01 != 0 {
			details = append(details, "anonymous login enabled (a null user name is accepted)")
		}
		if reply[23]&0x02 != 0 {
			details = append(details, "null user name with a non-null password enabled")
		}
		if reply[23]&0x04 != 0 {
			details = append(details, "per-message authentication disabled")
		}
	}

	f := t.Finding(strings.Join(details, "\n"))
	if len(reply) >= 25 && reply[23]&0x01 != 0 {
		// A BMC that accepts an anonymous login is not merely exposed.
		f.Severity = model.SevHigh
	}
	return []model.Finding{f}
}

// ipmiAuthTypeNames decodes the IPMI v1.5 authentication type support bitmap.
func ipmiAuthTypeNames(b byte) []string {
	var out []string
	for _, a := range []struct {
		bit  byte
		name string
	}{
		{0x01, "none"},
		{0x02, "MD2"},
		{0x04, "MD5"},
		{0x10, "straight password"},
		{0x20, "OEM"},
	} {
		if b&a.bit != 0 {
			out = append(out, a.name)
		}
	}
	return out
}
