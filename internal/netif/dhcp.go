package netif

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Minimal pure-Go BOOTP/DHCP (RFC 2131) message codec. It is used both by the
// raw-socket client (dhcp_linux.go) and by the lease-file parser, since
// dhcpcd stores the raw ACK packet on disk.

// DHCP message types (option 53).
type DHCPMessageType uint8

const (
	DHCPDiscover DHCPMessageType = 1
	DHCPOffer    DHCPMessageType = 2
	DHCPRequest  DHCPMessageType = 3
	DHCPDecline  DHCPMessageType = 4
	DHCPAck      DHCPMessageType = 5
	DHCPNak      DHCPMessageType = 6
	DHCPRelease  DHCPMessageType = 7
	DHCPInform   DHCPMessageType = 8
)

func (t DHCPMessageType) String() string {
	switch t {
	case DHCPDiscover:
		return "DISCOVER"
	case DHCPOffer:
		return "OFFER"
	case DHCPRequest:
		return "REQUEST"
	case DHCPDecline:
		return "DECLINE"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	case DHCPRelease:
		return "RELEASE"
	case DHCPInform:
		return "INFORM"
	}
	return "UNKNOWN"
}

// DHCP option codes used here.
const (
	OptSubnetMask     uint8 = 1
	OptRouter         uint8 = 3
	OptDNSServers     uint8 = 6
	OptHostname       uint8 = 12
	OptDomainName     uint8 = 15
	OptBroadcastAddr  uint8 = 28
	OptRequestedIP    uint8 = 50
	OptLeaseTime      uint8 = 51
	OptMessageType    uint8 = 53
	OptServerID       uint8 = 54
	OptParamReqList   uint8 = 55
	OptMessage        uint8 = 56
	OptMaxMessageSize uint8 = 57
	OptRenewalTime    uint8 = 58
	OptRebindingTime  uint8 = 59
	OptVendorClass    uint8 = 60
	OptClientID       uint8 = 61
	OptDomainSearch   uint8 = 119
	OptEnd            uint8 = 255
)

const dhcpMagicCookie uint32 = 0x63825363

// ErrNotDHCP is returned when a buffer is not a BOOTP/DHCP message.
var ErrNotDHCP = errors.New("netif: not a DHCP message")

// DHCPMessage is a decoded BOOTP/DHCP packet.
type DHCPMessage struct {
	Op      uint8 // 1 = BOOTREQUEST, 2 = BOOTREPLY
	HType   uint8
	HLen    uint8
	Hops    uint8
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  netip.Addr
	YIAddr  netip.Addr
	SIAddr  netip.Addr
	GIAddr  netip.Addr
	CHAddr  net.HardwareAddr
	Options map[uint8][]byte
	// Order preserves the option order for deterministic marshalling.
	order []uint8
}

// SetOption sets (or replaces) an option, keeping insertion order.
func (m *DHCPMessage) SetOption(code uint8, val []byte) {
	if m.Options == nil {
		m.Options = make(map[uint8][]byte)
	}
	if _, ok := m.Options[code]; !ok {
		m.order = append(m.order, code)
	}
	m.Options[code] = val
}

// Type returns the DHCP message type (option 53), 0 when absent.
func (m *DHCPMessage) Type() DHCPMessageType {
	if v, ok := m.Options[OptMessageType]; ok && len(v) >= 1 {
		return DHCPMessageType(v[0])
	}
	return 0
}

// optAddr decodes a 4-byte option as an IPv4 address.
func (m *DHCPMessage) optAddr(code uint8) netip.Addr {
	v, ok := m.Options[code]
	if !ok || len(v) < 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(v[:4]))
}

func (m *DHCPMessage) optAddrs(code uint8) []netip.Addr {
	v := m.Options[code]
	out := make([]netip.Addr, 0, len(v)/4)
	for i := 0; i+4 <= len(v); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(v[i:i+4])))
	}
	return out
}

func (m *DHCPMessage) optUint32(code uint8) (uint32, bool) {
	v, ok := m.Options[code]
	if !ok || len(v) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(v[:4]), true
}

// Lease derives a Lease from an OFFER/ACK. now is used to turn the relative
// lease timers into absolute instants.
func (m *DHCPMessage) Lease(iface string, now time.Time) Lease {
	l := Lease{Interface: iface, Address: m.YIAddr.Unmap()}
	if !l.Address.IsValid() || l.Address.IsUnspecified() {
		l.Address = m.CIAddr.Unmap()
	}
	if mask, ok := m.Options[OptSubnetMask]; ok && len(mask) >= 4 && l.Address.IsValid() {
		bits := net.IPv4Mask(mask[0], mask[1], mask[2], mask[3])
		if ones, _ := bits.Size(); ones > 0 || isZeroMask(mask[:4]) {
			l.Prefix = netip.PrefixFrom(l.Address, ones)
		}
	}
	l.Router = m.optAddr(OptRouter)
	l.Server = m.optAddr(OptServerID)
	if !l.Server.IsValid() {
		l.Server = m.SIAddr.Unmap()
	}
	l.DNS = m.optAddrs(OptDNSServers)
	if v, ok := m.Options[OptDomainName]; ok {
		l.DomainName = trimNUL(string(v))
	}
	if v, ok := m.Options[OptDomainSearch]; ok {
		l.Search = parseDomainSearch(v)
	}
	if secs, ok := m.optUint32(OptLeaseTime); ok && secs > 0 {
		l.Expire = now.Add(time.Duration(secs) * time.Second)
	}
	if secs, ok := m.optUint32(OptRenewalTime); ok && secs > 0 {
		l.Renew = now.Add(time.Duration(secs) * time.Second)
	}
	if secs, ok := m.optUint32(OptRebindingTime); ok && secs > 0 {
		l.Rebind = now.Add(time.Duration(secs) * time.Second)
	}
	return l
}

func isZeroMask(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func trimNUL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == 0 || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

// parseDomainSearch decodes RFC 3397 / RFC 1035 compressed domain lists.
func parseDomainSearch(b []byte) []string {
	var out []string
	for i := 0; i < len(b); {
		name, next, ok := readDNSName(b, i, 0)
		if !ok {
			break
		}
		if name != "" {
			out = appendUniqueString(out, name)
		}
		if next <= i {
			break
		}
		i = next
	}
	return out
}

func readDNSName(b []byte, i, depth int) (string, int, bool) {
	if depth > 8 {
		return "", 0, false
	}
	var labels []string
	for i < len(b) {
		n := int(b[i])
		switch {
		case n == 0:
			return joinLabels(labels), i + 1, true
		case n&0xc0 == 0xc0:
			if i+1 >= len(b) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(b[i:i+2]) & 0x3fff)
			if ptr >= len(b) {
				return "", 0, false
			}
			tail, _, ok := readDNSName(b, ptr, depth+1)
			if !ok {
				return "", 0, false
			}
			if tail != "" {
				labels = append(labels, tail)
			}
			return joinLabels(labels), i + 2, true
		default:
			if i+1+n > len(b) {
				return "", 0, false
			}
			labels = append(labels, string(b[i+1:i+1+n]))
			i += 1 + n
		}
	}
	return "", 0, false
}

func joinLabels(labels []string) string {
	s := ""
	for i, l := range labels {
		if i > 0 {
			s += "."
		}
		s += l
	}
	return s
}

// ParseDHCPMessage decodes a BOOTP/DHCP message (the UDP payload).
func ParseDHCPMessage(b []byte) (*DHCPMessage, error) {
	if len(b) < 240 {
		return nil, ErrNotDHCP
	}
	if binary.BigEndian.Uint32(b[236:240]) != dhcpMagicCookie {
		return nil, ErrNotDHCP
	}
	m := &DHCPMessage{
		Op:      b[0],
		HType:   b[1],
		HLen:    b[2],
		Hops:    b[3],
		XID:     binary.BigEndian.Uint32(b[4:8]),
		Secs:    binary.BigEndian.Uint16(b[8:10]),
		Flags:   binary.BigEndian.Uint16(b[10:12]),
		CIAddr:  netip.AddrFrom4([4]byte(b[12:16])),
		YIAddr:  netip.AddrFrom4([4]byte(b[16:20])),
		SIAddr:  netip.AddrFrom4([4]byte(b[20:24])),
		GIAddr:  netip.AddrFrom4([4]byte(b[24:28])),
		Options: make(map[uint8][]byte),
	}
	hlen := int(m.HLen)
	if hlen < 0 || hlen > 16 {
		hlen = 6
	}
	m.CHAddr = net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...))

	for i := 240; i < len(b); {
		code := b[i]
		if code == 0 { // pad
			i++
			continue
		}
		if code == OptEnd {
			break
		}
		if i+2 > len(b) {
			break
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			break
		}
		val := append([]byte(nil), b[i+2:i+2+n]...)
		// RFC 3396: repeated options concatenate.
		if prev, ok := m.Options[code]; ok {
			m.Options[code] = append(prev, val...)
		} else {
			m.Options[code] = val
			m.order = append(m.order, code)
		}
		i += 2 + n
	}
	return m, nil
}

// Marshal encodes the message. Options longer than 255 bytes are split per
// RFC 3396.
func (m *DHCPMessage) Marshal() []byte {
	b := make([]byte, 240, 548)
	b[0] = m.Op
	b[1] = m.HType
	if b[1] == 0 {
		b[1] = 1 // ethernet
	}
	b[2] = m.HLen
	if b[2] == 0 {
		b[2] = byte(len(m.CHAddr))
	}
	b[3] = m.Hops
	binary.BigEndian.PutUint32(b[4:8], m.XID)
	binary.BigEndian.PutUint16(b[8:10], m.Secs)
	binary.BigEndian.PutUint16(b[10:12], m.Flags)
	putAddr4(b[12:16], m.CIAddr)
	putAddr4(b[16:20], m.YIAddr)
	putAddr4(b[20:24], m.SIAddr)
	putAddr4(b[24:28], m.GIAddr)
	copy(b[28:44], m.CHAddr)
	binary.BigEndian.PutUint32(b[236:240], dhcpMagicCookie)

	for _, code := range m.order {
		val := m.Options[code]
		for {
			n := len(val)
			if n > 255 {
				n = 255
			}
			b = append(b, code, byte(n))
			b = append(b, val[:n]...)
			val = val[n:]
			if len(val) == 0 {
				break
			}
		}
	}
	b = append(b, OptEnd)
	// BOOTP minimum payload.
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b
}

func putAddr4(dst []byte, a netip.Addr) {
	a = a.Unmap()
	if a.Is4() {
		v := a.As4()
		copy(dst, v[:])
	}
}

// NewDHCPDiscover builds a DISCOVER for mac.
func NewDHCPDiscover(xid uint32, mac net.HardwareAddr, hostname string) *DHCPMessage {
	m := baseRequest(xid, mac, hostname)
	m.SetOption(OptMessageType, []byte{byte(DHCPDiscover)})
	m.SetOption(OptParamReqList, defaultParamReqList())
	m.SetOption(OptMaxMessageSize, []byte{0x02, 0x40}) // 576
	return m
}

// NewDHCPRequest builds the REQUEST answering an OFFER.
func NewDHCPRequest(xid uint32, mac net.HardwareAddr, hostname string, requested, server netip.Addr) *DHCPMessage {
	m := baseRequest(xid, mac, hostname)
	m.SetOption(OptMessageType, []byte{byte(DHCPRequest)})
	if requested.Is4() {
		v := requested.As4()
		m.SetOption(OptRequestedIP, v[:])
	}
	if server.Is4() {
		v := server.As4()
		m.SetOption(OptServerID, v[:])
	}
	m.SetOption(OptParamReqList, defaultParamReqList())
	m.SetOption(OptMaxMessageSize, []byte{0x02, 0x40})
	return m
}

// NewDHCPRelease builds the RELEASE that gives a lease back when NETY is done
// with a temporary sub-interface.
func NewDHCPRelease(xid uint32, mac net.HardwareAddr, client, server netip.Addr) *DHCPMessage {
	m := baseRequest(xid, mac, "")
	m.CIAddr = client
	m.SetOption(OptMessageType, []byte{byte(DHCPRelease)})
	if server.Is4() {
		v := server.As4()
		m.SetOption(OptServerID, v[:])
	}
	return m
}

func baseRequest(xid uint32, mac net.HardwareAddr, hostname string) *DHCPMessage {
	m := &DHCPMessage{
		Op:     1,
		HType:  1,
		HLen:   byte(len(mac)),
		XID:    xid,
		Flags:  0x8000, // broadcast: the sub-interface has no address yet
		CHAddr: mac,
	}
	// Client identifier = 0x01 (ethernet) + MAC, like ISC dhclient.
	m.SetOption(OptClientID, append([]byte{1}, mac...))
	if hostname != "" {
		m.SetOption(OptHostname, []byte(hostname))
	}
	return m
}

func defaultParamReqList() []byte {
	return []byte{
		OptSubnetMask, OptRouter, OptDNSServers, OptDomainName,
		OptBroadcastAddr, OptLeaseTime, OptServerID,
		OptRenewalTime, OptRebindingTime, OptDomainSearch,
	}
}
