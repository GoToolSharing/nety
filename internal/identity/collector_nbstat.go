package identity

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/smb"
	"github.com/GoToolSharing/nety/internal/model"
)

// nbName is one entry of an NBSTAT node status response.
type nbName struct {
	Name   string
	Suffix byte
	Group  bool
	Flags  uint16
}

// nbstatResult is a decoded NBSTAT response.
type nbstatResult struct {
	Names []nbName
	MAC   string // "" when zero / absent
}

func buildNBSTATQuery(id uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	b = append(b, smb.EncodeNetBIOSName("*", 0)...)
	return append(b, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
}

// skipDNSName returns the offset after a (possibly compressed) DNS name.
func skipDNSName(b []byte, off int) (int, error) {
	for i := 0; i < 128; i++ {
		if off >= len(b) {
			return 0, errors.New("nbstat: truncated name")
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(b) {
				return 0, errors.New("nbstat: truncated pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("nbstat: bad label")
		default:
			off += 1 + l
		}
	}
	return 0, errors.New("nbstat: name too long")
}

// parseNBSTAT decodes a node status response.
func parseNBSTAT(b []byte, wantID uint16) (*nbstatResult, error) {
	if len(b) < 12 {
		return nil, errors.New("nbstat: short response")
	}
	if binary.BigEndian.Uint16(b[0:]) != wantID {
		return nil, errors.New("nbstat: transaction id mismatch")
	}
	flags := binary.BigEndian.Uint16(b[2:])
	if flags&0x8000 == 0 {
		return nil, errors.New("nbstat: not a response")
	}
	if rc := flags & 0x000f; rc != 0 {
		return nil, fmt.Errorf("nbstat: rcode %d", rc)
	}
	off := 12
	// Skip questions if echoed (non-standard but seen).
	qd := int(binary.BigEndian.Uint16(b[4:]))
	for i := 0; i < qd && i < 4; i++ {
		var err error
		if off, err = skipDNSName(b, off); err != nil {
			return nil, err
		}
		off += 4
	}
	if binary.BigEndian.Uint16(b[6:]) == 0 {
		return nil, errors.New("nbstat: no answer")
	}
	off, err := skipDNSName(b, off)
	if err != nil {
		return nil, err
	}
	if off+10 > len(b) {
		return nil, errors.New("nbstat: truncated RR")
	}
	if typ := binary.BigEndian.Uint16(b[off:]); typ != 0x21 {
		return nil, fmt.Errorf("nbstat: unexpected RR type %d", typ)
	}
	rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
	off += 10
	if off+rdlen > len(b) {
		rdlen = len(b) - off
	}
	rd := b[off : off+rdlen]
	if len(rd) < 1 {
		return nil, errors.New("nbstat: empty rdata")
	}
	n := int(rd[0])
	res := &nbstatResult{}
	p := 1
	for i := 0; i < n && p+18 <= len(rd); i++ {
		raw := rd[p : p+15]
		name := strings.TrimRight(strings.Map(func(r rune) rune {
			if r < 0x20 || r >= 0x7f {
				return -1
			}
			return r
		}, string(raw)), " ")
		fl := binary.BigEndian.Uint16(rd[p+16:])
		res.Names = append(res.Names, nbName{Name: name, Suffix: rd[p+15], Group: fl&0x8000 != 0, Flags: fl})
		p += 18
	}
	if p+6 <= len(rd) {
		mac := rd[p : p+6]
		if !allZeroBytes(mac) && !(mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff) {
			res.MAC = net.HardwareAddr(mac).String()
		}
	}
	return res, nil
}

func allZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// nbstatEvidence converts a NBSTAT result into evidence.
func nbstatEvidence(sink *evidenceSink, r *nbstatResult, source string) {
	var computer, domain string
	var isDC, isPDC, isMB, isFS bool
	var all, users []string
	for _, n := range r.Names {
		if n.Name == "" {
			continue
		}
		all = append(all, fmt.Sprintf("%s<%02x>%s", n.Name, n.Suffix, map[bool]string{true: "G", false: ""}[n.Group]))
		switch {
		case n.Suffix == 0x00 && !n.Group && computer == "" && !strings.HasPrefix(n.Name, "IS~"):
			computer = n.Name
		case n.Suffix == 0x00 && n.Group && domain == "":
			domain = n.Name
		case n.Suffix == 0x1c && n.Group:
			isDC = true
			if domain == "" {
				domain = n.Name
			}
		case n.Suffix == 0x1b && !n.Group:
			isPDC = true
		case n.Suffix == 0x1d:
			isMB = true
		case n.Suffix == 0x20 && !n.Group:
			isFS = true
			if computer == "" {
				computer = n.Name
			}
		case n.Suffix == 0x03 && !n.Group:
			users = append(users, n.Name)
		}
	}
	sort.Strings(all)
	attrs := map[string]string{"names": strings.Join(all, ",")}
	if domain != "" {
		attrs["domain"] = domain
	}
	if isDC {
		attrs["dc"] = "true"
	}
	if isPDC {
		attrs["domain_master_browser"] = "true"
	}
	if isMB {
		attrs["master_browser"] = "true"
	}
	if isFS {
		attrs["file_server"] = "true"
	}
	if len(users) > 0 {
		sort.Strings(users)
		attrs["messenger_names"] = strings.Join(users, ",")
	}
	if computer != "" {
		sink.add(model.EvNetBIOSName, computer, source, 80, attrs)
		sink.add(model.EvHostname, strings.ToLower(computer), source, 70, nil)
	}
	if domain != "" && !strings.EqualFold(domain, computer) {
		sink.add(model.EvNetBIOSDomain, domain, source, 75, nil)
	}
	if r.MAC != "" {
		sink.add(model.EvMAC, r.MAC, source, 85, map[string]string{"source": "nbstat"})
	}
}

// probeNBSTAT sends one NetBIOS node status query (UDP 137).
func (c *collector) probeNBSTAT(ctx context.Context, sink *evidenceSink, ip string, port int) error {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	resp, err := udpExchange(ctx, net.JoinHostPort(ip, strconv.Itoa(port)), buildNBSTATQuery(id), c.ioTimeout)
	if err != nil {
		return err
	}
	r, err := parseNBSTAT(resp, id)
	if err != nil {
		return err
	}
	nbstatEvidence(sink, r, "nbstat/"+strconv.Itoa(port))
	return nil
}

// udpExchange sends one datagram and waits for one reply from the peer.
func udpExchange(ctx context.Context, addr string, req []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
