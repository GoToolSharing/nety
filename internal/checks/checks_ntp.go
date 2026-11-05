package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ntp-monlist", "NTP server answers the mode 7 monlist query", model.SevMedium,
			[]string{"ntp"},
			"The NTP daemon answers the legacy mode 7 monlist request, which returns the last clients that asked it for the time. Two things follow. The reply is many times larger than the request and the request is a single UDP packet, so the service is a ready-made amplifier for a spoofed-source denial of service against anyone on the internet or on this network. And the list itself is an inventory: it names internal hosts that this address has spoken to, including segments the scan cannot reach, which is exactly the map an attacker wants before moving."),
		Remediation: "Upgrade to ntpd 4.2.7p26 or later, where mode 7 monlist is gone, or disable the query on the running version with 'disable monitor' in ntp.conf plus 'restrict default noquery nomodify notrap'. Consider chrony or the systemd timesync client on hosts that only need to read the time, and block inbound UDP 123 to clients at the network edge.",
		References: []string{
			"https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211",
			"https://support.ntp.org/Support/DRDoS",
		},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.UDP, []string{"ntp"}, 123)
		},
		Run: runNTPMonlist,
	})
}

// ntpMonlistRequest is a single mode 7 (private) MON_GETLIST_1 request:
// version 2, mode 7, implementation 3 (XNTPD), request code 42. It asks a question and
// changes nothing; the mode 7 calls that reconfigure a daemon are a different request
// code and are never sent.
var ntpMonlistRequest = func() []byte {
	b := make([]byte, 48)
	b[0] = 0x17 // response=0, more=0, version=2, mode=7
	b[1] = 0x00 // auth=0, sequence=0
	b[2] = 0x03 // implementation: XNTPD
	b[3] = 0x2a // request code 42: MON_GETLIST_1
	return b
}()

// ntpMonItemSize is the size of one info_monitor_1 entry.
const ntpMonItemSize = 72

func runNTPMonlist(ctx context.Context, t *Target) []model.Finding {
	c, err := t.DialUDP(ctx, t.Service.Port)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write(ntpMonlistRequest); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := readWithDeadline(c, t.Timeout, buf)
	if err != nil {
		t.Log.Debug("ntp monlist: no answer", "err", err)
		return nil
	}
	peers, count, size, err := ntpParseMonlist(buf[:n])
	if err != nil {
		t.Log.Debug("ntp monlist: not a monlist reply", "err", err)
		return nil
	}

	var ev strings.Builder
	fmt.Fprintf(&ev, "A %d byte mode 7 MON_GETLIST_1 request was answered with %d bytes carrying %d entries of %d bytes.\n",
		len(ntpMonlistRequest), n, count, size)
	fmt.Fprintf(&ev, "Amplification from this one packet: %.1fx, and ntpd sends the rest of the list in further packets.\n",
		float64(n)/float64(len(ntpMonlistRequest)))
	if len(peers) > 0 {
		sort.Strings(peers)
		fmt.Fprintf(&ev, "Clients disclosed (%d in this packet): %s\n", len(peers), strings.Join(limitStrings(peers, 20), ", "))
	}
	ev.WriteString("One request was sent and the answer was read once; the query was not repeated.")
	return []model.Finding{t.Finding(ev.String())}
}

// ntpParseMonlist decodes a mode 7 reply and extracts the client addresses.
func ntpParseMonlist(b []byte) (peers []string, count, size int, err error) {
	if len(b) < 8 {
		return nil, 0, 0, fmt.Errorf("ntp: reply too short (%d bytes)", len(b))
	}
	// Byte 0: response(1) more(1) version(3) mode(3).
	if b[0]&0x80 == 0 || b[0]&0x07 != 7 {
		return nil, 0, 0, fmt.Errorf("ntp: not a mode 7 response (0x%02x)", b[0])
	}
	if b[2] != 0x03 || b[3] != 0x2a {
		return nil, 0, 0, fmt.Errorf("ntp: reply to another request (impl %d, code %d)", b[2], b[3])
	}
	if e := b[4] >> 4; e != 0 {
		return nil, 0, 0, fmt.Errorf("ntp: monlist refused (error %d)", e)
	}
	count = int(binary.BigEndian.Uint16(b[4:]) & 0x0fff)
	size = int(binary.BigEndian.Uint16(b[6:]) & 0x0fff)
	if count == 0 || size == 0 {
		return nil, count, size, fmt.Errorf("ntp: empty monlist")
	}
	data := b[8:]
	if size*count > len(data) {
		// A truncated datagram is still proof the query is answered; read whatever
		// entries arrived whole.
		count = len(data) / size
	}
	if size != ntpMonItemSize {
		// A different ntpd build lays the entry out differently. The count is the
		// evidence that matters, so do not guess at the addresses.
		return nil, count, size, nil
	}
	seen := map[string]bool{}
	for i := 0; i < count && i < 64; i++ {
		e := data[i*size : (i+1)*size]
		var addr netip.Addr
		if binary.BigEndian.Uint32(e[32:]) != 0 {
			addr = netip.AddrFrom16([16]byte(e[40:56]))
		} else {
			addr = netip.AddrFrom4([4]byte(e[16:20]))
		}
		s := addr.Unmap().String()
		if !addr.IsValid() || addr.IsUnspecified() || seen[s] {
			continue
		}
		seen[s] = true
		peers = append(peers, s)
	}
	return peers, count, size, nil
}
