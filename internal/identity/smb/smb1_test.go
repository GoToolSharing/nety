package smb

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/identity/ntlm"
)

func smb1RespHeader(cmd byte, flags2 uint16, status uint32) []byte {
	h := make([]byte, 32)
	copy(h, []byte{0xff, 'S', 'M', 'B'})
	h[4] = cmd
	binary.LittleEndian.PutUint32(h[5:], status)
	h[9] = 0x98
	binary.LittleEndian.PutUint16(h[10:], flags2)
	binary.LittleEndian.PutUint16(h[28:], 2048)
	return h
}

func buildSMB1NegResp(unicode bool) []byte {
	flags2 := uint16(0x4001)
	if unicode {
		flags2 |= 0x8000
	}
	b := smb1RespHeader(0x72, flags2, 0)
	w := make([]byte, 34)
	w[2] = 0x03 | 0x04 // user level, encrypt, signing enabled
	binary.LittleEndian.PutUint32(w[7:], 16644)
	binary.LittleEndian.PutUint32(w[19:], 0x0000e3fd)
	binary.LittleEndian.PutUint64(w[23:], ntlm.TimeToFiletime(time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)))
	binary.LittleEndian.PutUint16(w[31:], uint16(0xffc4)) // -60
	w[33] = 8
	b = append(b, 17)
	b = append(b, w...)
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if unicode {
		data = append(data, ntlm.EncodeUTF16("WORKGROUP\x00")...)
		data = append(data, ntlm.EncodeUTF16("OLDBOX\x00")...)
	} else {
		data = append(data, []byte("WORKGROUP\x00OLDBOX\x00")...)
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func buildSMB1SessResp(unicode bool) []byte {
	flags2 := uint16(0x4001)
	if unicode {
		flags2 |= 0x8000
	}
	b := smb1RespHeader(0x73, flags2, 0)
	b = append(b, 3, 0xff, 0, 0, 0, 1, 0) // wc=3, andx none, action=guest
	var data []byte
	if unicode {
		data = append(data, 0) // pad: bytes start at odd offset 41
		data = append(data, ntlm.EncodeUTF16("Windows 5.1\x00Windows 2000 LAN Manager\x00WORKGROUP\x00")...)
	} else {
		data = []byte("Windows Server 2003 3790 Service Pack 2\x00Windows Server 2003 5.2\x00CORP\x00")
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func TestParseSMB1(t *testing.T) {
	for _, uni := range []bool{false, true} {
		info, uid, err := ParseSMB1Negotiate(buildSMB1NegResp(uni))
		if err != nil {
			t.Fatal(err)
		}
		if uid != 2048 || info.Domain != "WORKGROUP" || info.Server != "OLDBOX" || !info.SigningEnabled || info.SigningRequired {
			t.Fatalf("uni=%v %+v", uni, info)
		}
		if info.TimeZoneMinutes != -60 || info.SystemTime.Year() != 2024 || len(info.Challenge) != 8 {
			t.Fatalf("%+v", info)
		}
		if err := ParseSMB1SessionSetup(buildSMB1SessResp(uni), info); err != nil {
			t.Fatal(err)
		}
		if uni && (info.NativeOS != "Windows 5.1" || info.NativeLanMan != "Windows 2000 LAN Manager" || info.PrimaryDomain != "WORKGROUP") {
			t.Fatalf("%+v", info)
		}
		if !uni && (info.NativeOS != "Windows Server 2003 3790 Service Pack 2" || info.PrimaryDomain != "CORP") {
			t.Fatalf("%+v", info)
		}
		if !info.Guest || !info.SessionOK {
			t.Fatal("guest")
		}
	}
}

func TestParseSMB1Hostile(t *testing.T) {
	for _, m := range [][]byte{buildSMB1NegResp(true), buildSMB1SessResp(true), buildSMB1NegResp(false)} {
		for i := 0; i <= len(m); i++ {
			info := &SMB1Info{}
			_, _, _ = ParseSMB1Negotiate(m[:i])
			_ = ParseSMB1SessionSetup(m[:i], info)
		}
		seed := uint32(7)
		for n := 0; n < 2000; n++ {
			x := append([]byte(nil), m...)
			for k := 0; k < 3; k++ {
				seed = seed*1664525 + 1013904223
				p := int(seed>>8) % len(x)
				if p < 4 {
					continue
				}
				x[p] = byte(seed >> 16)
			}
			_, _, _ = ParseSMB1Negotiate(x)
			_ = ParseSMB1SessionSetup(x, &SMB1Info{})
		}
	}
	if _, _, err := ParseSMB1Negotiate(smb1RespHeader(0x72, 0, 0xc0000022)); err == nil {
		t.Fatal("error status accepted")
	}
}

func TestSMB1ProbeFakeServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tr := NewTransport(c, 2*time.Second)
		for _, resp := range [][]byte{buildSMB1NegResp(true), buildSMB1SessResp(true)} {
			req, err := tr.Recv()
			if err != nil || !IsSMB1(req) {
				return
			}
			if err := tr.Send(resp); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, c)
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	info, err := SMB1Probe(context.Background(), "127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.NativeOS != "Windows 5.1" || info.Server != "OLDBOX" {
		t.Fatalf("%+v", info)
	}
}

func TestSMB1Requests(t *testing.T) {
	n := BuildSMB1Negotiate()
	if !IsSMB1(n) || n[4] != 0x72 || binary.LittleEndian.Uint16(n[10:])&smb1Flags2ExtSecurity != 0 {
		t.Fatal("negotiate")
	}
	s := BuildSMB1SessionSetupAnon(5)
	r, err := parseSMB1(s)
	if err != nil || len(r.words) != 26 || r.uid != 5 {
		t.Fatalf("session setup %v", err)
	}
}
