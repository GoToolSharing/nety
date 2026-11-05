package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("cisco-smart-install", "Cisco Smart Install client active", model.SevHigh,
			[]string{"smart-install", "unknown"},
			"The Cisco Smart Install client is listening on TCP 4786. Smart Install is a zero-touch provisioning feature that trusts whoever reaches it: an unauthenticated peer can make the switch upload its running configuration to a TFTP server of the attacker's choosing, replace that configuration, or load a new IOS image and reload. The running configuration carries the enable secret, the SNMP communities and the VLAN layout, so on an internal network one reachable switch is usually enough to take the network apart. The feature stays on after a switch is deployed unless it is explicitly disabled."),
		Remediation: "Disable the client on every switch that is not actively being provisioned: 'no vstack' in global configuration. Where Smart Install is genuinely in use, confine TCP 4786 to the director with an infrastructure ACL and keep IOS current.",
		References: []string{
			"https://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html",
			"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi",
		},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"smart-install", "smartinstall", "vstack"}, 4786)
		},
		Run: runCiscoSmartInstall,
	})
}

// smiProbe is the Smart Install protocol hello: header version 1, message
// type 1 (a capability query), no payload beyond the fixed fields. It asks
// the switch what it is, and nothing more. The destructive side of Smart
// Install lives in the later "copy config" and "image load" messages, which
// NETY does not send.
var smiProbe = []byte{
	0x00, 0x00, 0x00, 0x01, // version
	0x00, 0x00, 0x00, 0x01, // message type: hello request
	0x00, 0x00, 0x00, 0x00, // reserved
	0x00, 0x00, 0x00, 0x08, // payload length
	0x00, 0x00, 0x00, 0x01, // payload: capability request
	0x00, 0x00, 0x00, 0x00,
}

// smiHelloReply is the message type the client answers a hello with.
const smiHelloReply = 4

func runCiscoSmartInstall(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write(smiProbe); err != nil {
		return nil
	}
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Log.Debug("smart install: no answer", "err", err)
		return nil
	}
	ver := binary.BigEndian.Uint32(hdr[0:])
	msg := binary.BigEndian.Uint32(hdr[4:])
	// The reply is the Smart Install framing and nothing else looks like it:
	// protocol version 1 with the hello reply message type.
	if ver != 1 || msg != smiHelloReply {
		t.Log.Debug("smart install: unexpected framing", "version", ver, "message", msg)
		return nil
	}
	ev := fmt.Sprintf("Smart Install hello on %d/tcp was answered with the client's hello reply (protocol version %d, message type %d).\n"+
		"Only the hello was sent: no configuration copy, image load or reload message was issued.", t.Service.Port, ver, msg)
	return []model.Finding{t.Finding(ev)}
}
