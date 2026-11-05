package netif

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/GoToolSharing/nety/internal/model"
)

// This file decodes the switch-port control plane from raw Ethernet frames. It is
// deliberately platform independent: the AF_PACKET plumbing lives in sniff_linux.go and
// only hands complete frames to L2Collector.Consume, so every decoder below is
// unit-testable from byte fixtures on any OS.

// Well-known destination MACs.
var (
	// CDPMulticast is also used by DTP, VTP, PAgP and UDLD.
	CDPMulticast  = net.HardwareAddr{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	LLDPMulticast = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	STPMulticast  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}
)

// EtherTypes we care about.
const (
	etherTypeLLDP    = 0x88cc
	etherTypeDot1Q   = 0x8100
	etherTypeQinQ    = 0x88a8
	etherTypeDot1QAD = 0x9100 // legacy QinQ
)

// SNAP protocol IDs under OUI 00:00:0C (Cisco).
const (
	ciscoPIDCDP = 0x2000
	ciscoPIDDTP = 0x2004
)

var ciscoOUI = [3]byte{0x00, 0x00, 0x0c}

// --------------------------------------------------------------------------- Frame
// dissection ---------------------------------------------------------------------------

// L2Frame is the part of an Ethernet frame the collector needs.
type L2Frame struct {
	Dst, Src  net.HardwareAddr
	VLANs     []int  // outer-to-inner 802.1Q/QinQ tags
	EtherType uint16 // 0 when the frame is 802.3/LLC
	// LLC fields, valid when EtherType == 0.
	DSAP, SSAP byte
	SNAPOUI    [3]byte
	SNAPPID    uint16
	IsSNAP     bool
	Payload    []byte // after the ethertype, or after the LLC/SNAP header
}

var errShortFrame = errors.New("netif: short frame")

// DissectEthernet walks the Ethernet header, any stack of VLAN tags and the LLC/SNAP
// header. It never allocates a copy of the payload.
func DissectEthernet(b []byte) (L2Frame, error) {
	var f L2Frame
	if len(b) < 14 {
		return f, errShortFrame
	}
	f.Dst = net.HardwareAddr(b[0:6])
	f.Src = net.HardwareAddr(b[6:12])
	i := 12
	for range 4 { // bounded: refuse absurd tag stacks
		if i+2 > len(b) {
			return f, errShortFrame
		}
		et := binary.BigEndian.Uint16(b[i : i+2])
		if et != etherTypeDot1Q && et != etherTypeQinQ && et != etherTypeDot1QAD {
			break
		}
		if i+4 > len(b) {
			return f, errShortFrame
		}
		vid := int(binary.BigEndian.Uint16(b[i+2:i+4]) & 0x0fff)
		f.VLANs = append(f.VLANs, vid)
		i += 4
	}
	if i+2 > len(b) {
		return f, errShortFrame
	}
	et := binary.BigEndian.Uint16(b[i : i+2])
	i += 2
	if et > 1500 {
		f.EtherType = et
		f.Payload = b[i:]
		return f, nil
	}
	// 802.3 length field: an LLC header follows. Trim padding to the stated length when
	// the frame carries any.
	end := len(b)
	if i+int(et) <= len(b) {
		end = i + int(et)
	}
	llc := b[i:end]
	if len(llc) < 3 {
		return f, errShortFrame
	}
	f.DSAP, f.SSAP = llc[0], llc[1]
	ctrl := llc[2]
	hdr := 3
	if ctrl&0x03 != 0x03 { // I-format / S-format use a 2-byte control field
		hdr = 4
	}
	if len(llc) < hdr {
		return f, errShortFrame
	}
	if f.DSAP == 0xaa && f.SSAP == 0xaa {
		if len(llc) < hdr+5 {
			return f, errShortFrame
		}
		f.IsSNAP = true
		copy(f.SNAPOUI[:], llc[hdr:hdr+3])
		f.SNAPPID = binary.BigEndian.Uint16(llc[hdr+3 : hdr+5])
		f.Payload = llc[hdr+5:]
		return f, nil
	}
	f.Payload = llc[hdr:]
	return f, nil
}

// IsCDP / IsDTP / IsSTP / IsLLDP classify a dissected frame.
func (f L2Frame) IsCDP() bool {
	return f.IsSNAP && f.SNAPOUI == ciscoOUI && f.SNAPPID == ciscoPIDCDP
}
func (f L2Frame) IsDTP() bool {
	return f.IsSNAP && f.SNAPOUI == ciscoOUI && f.SNAPPID == ciscoPIDDTP
}
func (f L2Frame) IsSTP() bool {
	return !f.IsSNAP && f.EtherType == 0 && f.DSAP == 0x42 && f.SSAP == 0x42
}
func (f L2Frame) IsLLDP() bool { return f.EtherType == etherTypeLLDP }

// --------------------------------------------------------------------------- DTP
// ---------------------------------------------------------------------------

// DTP TLV types.
const (
	dtpTLVDomain   = 0x0001
	dtpTLVStatus   = 0x0002
	dtpTLVType     = 0x0003
	dtpTLVNeighbor = 0x0004
)

// DTPInfo is a decoded Dynamic Trunking Protocol advertisement. DTP is undocumented; the
// status octet is interpreted as
//
//	bit 7 (0x80) : the port is currently trunking
//	bits 0..2    : the administrative mode
//	               1 = on (static trunk), 2 = access (no negotiation),
//	               3 = desirable, 4 = auto
//
// which matches what Cisco switches emit and what Scapy's contrib/dtp.py sends to request
// a trunk (status 0x03, type 0xa5). Raw holds the octet so an operator can second-guess
// the mapping.
type DTPInfo struct {
	Version  uint8
	Domain   string
	Status   uint8
	Mode     string // on | access | desirable | auto | unknown(0x..)
	Trunking bool
	Type     uint8
	TypeName string // dot1q | isl | native | unknown(0x..)
	Neighbor net.HardwareAddr
}

// DTP administrative status values.
const (
	DTPStatusOn        uint8 = 0x01
	DTPStatusAccess    uint8 = 0x02
	DTPStatusDesirable uint8 = 0x03
	DTPStatusAuto      uint8 = 0x04
	dtpStatusTrunking  uint8 = 0x80
)

// DTP encapsulation type values.
const (
	DTPTypeNative uint8 = 0x05
	DTPTypeISL    uint8 = 0x42
	DTPTypeDot1Q  uint8 = 0xa5
)

// OffersTrunk reports whether the port is willing to form a trunk, i.e. the switch port
// is in on/desirable/auto rather than hard-coded access.
func (d DTPInfo) OffersTrunk() bool {
	switch d.Status & 0x07 {
	case DTPStatusOn, DTPStatusDesirable, DTPStatusAuto:
		return true
	}
	return false
}

// ParseDTP decodes the DTP payload (after the LLC/SNAP header).
func ParseDTP(b []byte) (DTPInfo, error) {
	var d DTPInfo
	if len(b) < 1 {
		return d, errShortFrame
	}
	d.Version = b[0]
	for i := 1; i+4 <= len(b); {
		typ := binary.BigEndian.Uint16(b[i : i+2])
		length := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if length < 4 || i+length > len(b) {
			break
		}
		val := b[i+4 : i+length]
		switch typ {
		case dtpTLVDomain:
			d.Domain = strings.TrimRight(string(val), "\x00")
		case dtpTLVStatus:
			if len(val) >= 1 {
				d.Status = val[0]
			}
		case dtpTLVType:
			if len(val) >= 1 {
				d.Type = val[0]
			}
		case dtpTLVNeighbor:
			if len(val) >= 6 {
				d.Neighbor = net.HardwareAddr(append([]byte(nil), val[:6]...))
			}
		}
		i += length
	}
	d.Trunking = d.Status&dtpStatusTrunking != 0
	d.Mode = dtpModeName(d.Status)
	d.TypeName = dtpTypeName(d.Type)
	return d, nil
}

func dtpModeName(status uint8) string {
	switch status & 0x07 {
	case DTPStatusOn:
		return "on"
	case DTPStatusAccess:
		return "access"
	case DTPStatusDesirable:
		return "desirable"
	case DTPStatusAuto:
		return "auto"
	}
	return fmt.Sprintf("unknown(0x%02x)", status)
}

func dtpTypeName(t uint8) string {
	switch t {
	case DTPTypeNative:
		return "native"
	case DTPTypeISL:
		return "isl"
	case DTPTypeDot1Q:
		return "dot1q"
	case 0:
		return ""
	}
	return fmt.Sprintf("unknown(0x%02x)", t)
}

// BuildDTPFrame builds a DTP advertisement with the given administrative status, as sent
// by the dtp-trunk technique (status DTPStatusDesirable) and by its cleanup (status
// DTPStatusAccess).
func BuildDTPFrame(src net.HardwareAddr, domain string, status, encap uint8) []byte {
	// Domain TLV is padded to 32 bytes + 4 header bytes, like IOS.
	dom := make([]byte, 32)
	copy(dom, domain)

	var p []byte
	p = append(p, 0x01) // version
	p = appendDTPTLV(p, dtpTLVDomain, dom)
	p = appendDTPTLV(p, dtpTLVStatus, []byte{status})
	p = appendDTPTLV(p, dtpTLVType, []byte{encap})
	nb := make([]byte, 6)
	copy(nb, src)
	p = appendDTPTLV(p, dtpTLVNeighbor, nb)

	// 802.3 length + LLC/SNAP header.
	body := make([]byte, 0, 8+len(p))
	body = append(body, 0xaa, 0xaa, 0x03)
	body = append(body, ciscoOUI[:]...)
	body = binary.BigEndian.AppendUint16(body, ciscoPIDDTP)
	body = append(body, p...)

	frame := make([]byte, 0, 14+len(body))
	frame = append(frame, CDPMulticast...)
	srcMAC := make([]byte, 6)
	copy(srcMAC, src)
	frame = append(frame, srcMAC...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(body)))
	frame = append(frame, body...)
	for len(frame) < 60 { // minimum Ethernet frame without FCS
		frame = append(frame, 0)
	}
	return frame
}

func appendDTPTLV(dst []byte, typ uint16, val []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(4+len(val)))
	return append(dst, val...)
}

// --------------------------------------------------------------------------- Collector
// ---------------------------------------------------------------------------

// L2Collector accumulates model.L2Info from raw frames. It is safe for concurrent use.
type L2Collector struct {
	mu        sync.Mutex
	neighbors map[string]model.L2Neighbor
	order     []string
	vlans     map[int]struct{}
	dtpSeen   bool
	dtpMode   string
	native    int
	voice     int
	stpRoot   string
	stpCost   uint32
	stpHave   bool
	frames    int
	// DTP holds the last decoded DTP advertisement, used by the dtp-trunk technique to
	// know the VTP domain to answer with.
	DTP DTPInfo
}

// NewL2Collector returns an empty collector.
func NewL2Collector() *L2Collector {
	return &L2Collector{neighbors: map[string]model.L2Neighbor{}, vlans: map[int]struct{}{}}
}

// Frames is the number of frames consumed (all frames, not only decoded ones).
func (c *L2Collector) Frames() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frames
}

// Consume dissects one raw Ethernet frame. Unparsable frames are ignored.
func (c *L2Collector) Consume(b []byte) {
	f, err := DissectEthernet(b)
	c.mu.Lock()
	c.frames++
	c.mu.Unlock()
	if err != nil {
		return
	}
	for _, v := range f.VLANs {
		if ValidVLANID(v) {
			c.mu.Lock()
			c.vlans[v] = struct{}{}
			c.mu.Unlock()
		}
	}
	switch {
	case f.IsCDP():
		if n, ok := decodeCDP(f.Payload); ok {
			c.addNeighbor(n)
		}
	case f.IsLLDP():
		if n, ok := decodeLLDP(f.Payload); ok {
			c.addNeighbor(n)
		}
	case f.IsDTP():
		if d, err := ParseDTP(f.Payload); err == nil {
			c.mu.Lock()
			c.dtpSeen = true
			c.dtpMode = d.Mode
			c.DTP = d
			c.mu.Unlock()
		}
	case f.IsSTP():
		c.consumeSTP(f.Payload)
	}
}

func (c *L2Collector) consumeSTP(payload []byte) {
	var stp layers.STP
	if err := stp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Keep the advertisement with the lowest root path cost: it comes from the port
	// closest to the root bridge.
	if !c.stpHave || stp.Cost < c.stpCost {
		c.stpHave = true
		c.stpCost = stp.Cost
		c.stpRoot = formatSwitchID(stp.RouteID)
	}
}

func formatSwitchID(id layers.STPSwitchID) string {
	return fmt.Sprintf("%d.%d/%s", id.Priority, id.SysID, id.HwAddr.String())
}

func (c *L2Collector) addNeighbor(n model.L2Neighbor) {
	key := n.Protocol + "|" + n.DeviceID + "|" + n.PortID
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.neighbors[key]; ok {
		n = mergeNeighbor(prev, n)
	} else {
		c.order = append(c.order, key)
	}
	c.neighbors[key] = n
	if n.NativeVLAN != 0 && c.native == 0 {
		c.native = n.NativeVLAN
	}
	if n.VoiceVLAN != 0 && c.voice == 0 {
		c.voice = n.VoiceVLAN
	}
}

func mergeNeighbor(old, new model.L2Neighbor) model.L2Neighbor {
	pick := func(a, b string) string {
		if b != "" {
			return b
		}
		return a
	}
	out := model.L2Neighbor{
		Protocol:    old.Protocol,
		DeviceID:    pick(old.DeviceID, new.DeviceID),
		PortID:      pick(old.PortID, new.PortID),
		Platform:    pick(old.Platform, new.Platform),
		Software:    pick(old.Software, new.Software),
		MgmtAddress: pick(old.MgmtAddress, new.MgmtAddress),
		NativeVLAN:  old.NativeVLAN,
		VoiceVLAN:   old.VoiceVLAN,
	}
	if new.NativeVLAN != 0 {
		out.NativeVLAN = new.NativeVLAN
	}
	if new.VoiceVLAN != 0 {
		out.VoiceVLAN = new.VoiceVLAN
	}
	out.Capabilities = old.Capabilities
	for _, c := range new.Capabilities {
		out.Capabilities = appendUniqueString(out.Capabilities, c)
	}
	return out
}

// LastDTP returns the most recent DTP advertisement decoded. The dtp-trunk technique uses
// the VTP domain and encapsulation it announces.
func (c *L2Collector) LastDTP() DTPInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.DTP
}

// Info returns the aggregated result. capturedAt is stamped only when at least one
// control frame was decoded.
func (c *L2Collector) Info(capturedAt time.Time) model.L2Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := model.L2Info{
		DTPSeen:       c.dtpSeen,
		DTPMode:       c.dtpMode,
		NativeVLAN:    c.native,
		VoiceVLAN:     c.voice,
		STPRootBridge: c.stpRoot,
	}
	for _, k := range c.order {
		info.Neighbors = append(info.Neighbors, c.neighbors[k])
	}
	for v := range c.vlans {
		info.ObservedVLANs = append(info.ObservedVLANs, v)
	}
	sort.Ints(info.ObservedVLANs)
	if len(info.Neighbors) > 0 || c.dtpSeen || c.stpRoot != "" || len(info.ObservedVLANs) > 0 {
		t := capturedAt
		info.CapturedAt = &t
	}
	return info
}

// --------------------------------------------------------------------------- CDP
// ---------------------------------------------------------------------------

func decodeCDP(payload []byte) (model.L2Neighbor, bool) {
	pkt := gopacket.NewPacket(payload, layers.LayerTypeCiscoDiscovery, gopacket.DecodeOptions{Lazy: false})
	l := pkt.Layer(layers.LayerTypeCiscoDiscoveryInfo)
	if l == nil {
		return model.L2Neighbor{}, false
	}
	info, ok := l.(*layers.CiscoDiscoveryInfo)
	if !ok {
		return model.L2Neighbor{}, false
	}
	n := model.L2Neighbor{
		Protocol:     "cdp",
		DeviceID:     strings.TrimSpace(info.DeviceID),
		PortID:       strings.TrimSpace(info.PortID),
		Platform:     strings.TrimSpace(info.Platform),
		Software:     firstLine(info.Version),
		NativeVLAN:   int(info.NativeVLAN),
		Capabilities: cdpCapabilities(info.Capabilities),
	}
	if n.DeviceID == "" {
		n.DeviceID = strings.TrimSpace(info.SysName)
	}
	if ip, ok := firstIP(info.MgmtAddresses, info.Addresses); ok {
		n.MgmtAddress = ip.String()
	}
	if info.VLANReply.VLAN != 0 {
		n.VoiceVLAN = int(info.VLANReply.VLAN)
	} else if info.VLANQuery.VLAN != 0 {
		n.VoiceVLAN = int(info.VLANQuery.VLAN)
	}
	if n.DeviceID == "" && n.PortID == "" {
		return n, false
	}
	return n, true
}

func cdpCapabilities(c layers.CDPCapabilities) []string {
	var out []string
	add := func(b bool, s string) {
		if b {
			out = append(out, s)
		}
	}
	add(c.L3Router, "router")
	add(c.TBBridge, "transparent-bridge")
	add(c.SPBridge, "source-route-bridge")
	add(c.L2Switch, "switch")
	add(c.IsHost, "host")
	add(c.IGMPFilter, "igmp")
	add(c.L1Repeater, "repeater")
	add(c.IsPhone, "phone")
	add(c.RemotelyManaged, "remotely-managed")
	return out
}

func firstIP(lists ...[]net.IP) (netip.Addr, bool) {
	for _, l := range lists {
		for _, ip := range l {
			if a, ok := netip.AddrFromSlice(ip); ok {
				a = a.Unmap()
				if a.IsValid() && !a.IsUnspecified() {
					return a, true
				}
			}
		}
	}
	return netip.Addr{}, false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(strings.TrimSuffix(s, ","))
}

// --------------------------------------------------------------------------- LLDP
// ---------------------------------------------------------------------------

func decodeLLDP(payload []byte) (model.L2Neighbor, bool) {
	pkt := gopacket.NewPacket(payload, layers.LayerTypeLinkLayerDiscovery, gopacket.DecodeOptions{Lazy: false})
	base, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery)
	if base == nil {
		return model.L2Neighbor{}, false
	}
	n := model.L2Neighbor{
		Protocol: "lldp",
		DeviceID: formatChassisID(base.ChassisID),
		PortID:   formatPortID(base.PortID),
	}
	if info, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo); info != nil {
		if info.SysName != "" {
			n.DeviceID = strings.TrimSpace(info.SysName)
		}
		if info.PortDescription != "" {
			n.PortID = strings.TrimSpace(info.PortDescription)
		}
		n.Platform = firstLine(info.SysDescription)
		n.Software = lldpSoftware(info.SysDescription)
		n.Capabilities = lldpCapabilities(info.SysCapabilities)
		if a, ok := lldpMgmtAddr(info.MgmtAddress); ok {
			n.MgmtAddress = a.String()
		}
		if d, err := info.Decode8021(); err == nil {
			n.NativeVLAN = int(d.PVID)
		}
		if m, err := info.DecodeMedia(); err == nil {
			p := m.NetworkPolicy
			if p.ApplicationType == layers.LLDPAppTypeVoice && p.VLANId != 0 {
				n.VoiceVLAN = int(p.VLANId)
			}
		}
	}
	if n.DeviceID == "" && n.PortID == "" {
		return n, false
	}
	return n, true
}

func lldpSoftware(sysDesc string) string {
	s := strings.TrimSpace(sysDesc)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}

func lldpCapabilities(sc layers.LLDPSysCapabilities) []string {
	var out []string
	add := func(b bool, s string) {
		if b {
			out = append(out, s)
		}
	}
	c := sc.EnabledCap
	empty := layers.LLDPCapabilities{}
	if c == empty {
		c = sc.SystemCap
	}
	add(c.Other, "other")
	add(c.Repeater, "repeater")
	add(c.Bridge, "switch")
	add(c.WLANAP, "wlan-ap")
	add(c.Router, "router")
	add(c.Phone, "phone")
	add(c.DocSis, "docsis")
	add(c.StationOnly, "station")
	add(c.CVLAN, "c-vlan")
	add(c.SVLAN, "s-vlan")
	add(c.TMPR, "tpmr")
	return out
}

func lldpMgmtAddr(m layers.LLDPMgmtAddress) (netip.Addr, bool) {
	switch len(m.Address) {
	case 4:
		return netip.AddrFrom4([4]byte(m.Address)), true
	case 16:
		return netip.AddrFrom16([16]byte(m.Address)), true
	}
	return netip.Addr{}, false
}

func formatChassisID(c layers.LLDPChassisID) string {
	switch c.Subtype {
	case layers.LLDPChassisIDSubTypeMACAddr:
		if len(c.ID) == 6 {
			return net.HardwareAddr(c.ID).String()
		}
	case layers.LLDPChassisIDSubTypeNetworkAddr:
		if a, ok := lldpNetworkAddr(c.ID); ok {
			return a.String()
		}
	}
	return printableID(c.ID)
}

func formatPortID(p layers.LLDPPortID) string {
	switch p.Subtype {
	case layers.LLDPPortIDSubtypeMACAddr:
		if len(p.ID) == 6 {
			return net.HardwareAddr(p.ID).String()
		}
	case layers.LLDPPortIDSubtypeNetworkAddr:
		if a, ok := lldpNetworkAddr(p.ID); ok {
			return a.String()
		}
	}
	return printableID(p.ID)
}

// lldpNetworkAddr decodes an IANA-family-prefixed address (1 = IPv4, 2 = IPv6).
func lldpNetworkAddr(b []byte) (netip.Addr, bool) {
	if len(b) < 2 {
		return netip.Addr{}, false
	}
	switch b[0] {
	case 1:
		if len(b) >= 5 {
			return netip.AddrFrom4([4]byte(b[1:5])), true
		}
	case 2:
		if len(b) >= 17 {
			return netip.AddrFrom16([16]byte(b[1:17])), true
		}
	}
	return netip.Addr{}, false
}

func printableID(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Sprintf("%x", b)
		}
	}
	return strings.TrimSpace(s)
}
