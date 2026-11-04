package segment

import (
	"encoding/binary"
	"strings"
)

// A UDP service only answers a probe it recognises, so an empty datagram would
// report "filtered" for every reachable UDP service. These payloads are the
// smallest well-formed request each common service replies to; anything else
// gets a single zero byte, which at least elicits an ICMP port-unreachable
// from a host that is reachable but not listening.
func udpPayload(port uint16, service string) []byte {
	switch strings.ToLower(service) {
	case "domain", "dns":
		return dnsQuery()
	case "ntp":
		return ntpClient()
	case "snmp":
		return snmpGetRequest()
	case "netbios-ns", "nbns":
		return netbiosStatusQuery()
	case "isakmp", "ike":
		return ikeSA()
	}
	switch port {
	case 53, 5353:
		return dnsQuery()
	case 123:
		return ntpClient()
	case 161:
		return snmpGetRequest()
	case 137:
		return netbiosStatusQuery()
	case 500, 4500:
		return ikeSA()
	case 1900:
		return ssdpDiscover()
	case 69:
		return tftpRead()
	}
	return []byte{0x00}
}

// dnsQuery is a standard recursion-desired A query for "version.bind" in the
// CHAOS class, which both resolvers and authoritative servers answer.
func dnsQuery() []byte {
	b := []byte{
		0x13, 0x37, // transaction id
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	b = append(b, 7, 'v', 'e', 'r', 's', 'i', 'o', 'n')
	b = append(b, 4, 'b', 'i', 'n', 'd', 0)
	b = append(b, 0x00, 0x10) // TXT
	b = append(b, 0x00, 0x03) // CHAOS
	return b
}

// ntpClient is a mode-3 (client) NTPv4 packet.
func ntpClient() []byte {
	b := make([]byte, 48)
	b[0] = 0x23 // LI 0, VN 4, mode 3
	return b
}

// snmpGetRequest asks for sysDescr.0 with the "public" community in SNMPv1.
func snmpGetRequest() []byte {
	return []byte{
		0x30, 0x26,
		0x02, 0x01, 0x00, // version 1 (0 = v1)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19,
		0x02, 0x04, 0x13, 0x37, 0x13, 0x37, // request id
		0x02, 0x01, 0x00, // error status
		0x02, 0x01, 0x00, // error index
		0x30, 0x0b,
		0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // 1.3.6.1.2.1
		0x05, 0x00,
	}
}

// netbiosStatusQuery is the NBSTAT wildcard query nbtscan sends.
func netbiosStatusQuery() []byte {
	b := []byte{0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Encoded name "*" padded with NULs (first-level encoding).
	b = append(b, 0x20, 0x43, 0x4b)
	for i := 0; i < 15; i++ {
		b = append(b, 0x41, 0x41)
	}
	b = append(b, 0x00)
	b = append(b, 0x00, 0x21) // NBSTAT
	b = append(b, 0x00, 0x01) // IN
	return b
}

// ikeSA is a minimal ISAKMP main-mode SA proposal.
func ikeSA() []byte {
	b := make([]byte, 0, 64)
	cookie := []byte{0x13, 0x37, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef}
	b = append(b, cookie...)
	b = append(b, make([]byte, 8)...) // responder cookie
	b = append(b, 0x01)               // next payload: SA
	b = append(b, 0x10)               // version 1.0
	b = append(b, 0x02)               // exchange type: identity protection
	b = append(b, 0x00)               // flags
	b = append(b, 0, 0, 0, 0)         // message id
	b = binary.BigEndian.AppendUint32(b, 0)
	binary.BigEndian.PutUint32(b[len(b)-4:], uint32(len(b)))
	return b
}

// ssdpDiscover is the SSDP M-SEARCH every UPnP device answers.
func ssdpDiscover() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n")
}

// tftpRead requests a file that will not exist, which yields an error packet
// from a live TFTP server.
func tftpRead() []byte {
	b := []byte{0x00, 0x01}
	b = append(b, "nety-probe"...)
	b = append(b, 0x00)
	b = append(b, "octet"...)
	b = append(b, 0x00)
	return b
}
