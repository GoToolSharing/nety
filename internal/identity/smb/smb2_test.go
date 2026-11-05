package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
)

var testGUID = []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

func respHeader(cmd uint16, status uint32, msgID uint64, tree uint32, sess uint64) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1)
	binary.LittleEndian.PutUint32(h[16:], 1) // response
	binary.LittleEndian.PutUint64(h[24:], msgID)
	binary.LittleEndian.PutUint32(h[36:], tree)
	binary.LittleEndian.PutUint64(h[40:], sess)
	return h
}

func negotiateResponse(msgID uint64, dialect uint16, secMode uint16) []byte {
	blob := ntlm.SPNEGOInit(nil)
	b := make([]byte, 64)
	binary.LittleEndian.PutUint16(b[0:], 65)
	binary.LittleEndian.PutUint16(b[2:], secMode)
	binary.LittleEndian.PutUint16(b[4:], dialect)
	copy(b[8:24], testGUID)
	binary.LittleEndian.PutUint32(b[24:], 0x2f)
	binary.LittleEndian.PutUint32(b[28:], 8388608)
	binary.LittleEndian.PutUint32(b[32:], 8388608)
	binary.LittleEndian.PutUint32(b[36:], 8388608)
	binary.LittleEndian.PutUint64(b[40:], ntlm.TimeToFiletime(time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)))
	binary.LittleEndian.PutUint16(b[56:], 128)
	binary.LittleEndian.PutUint16(b[58:], uint16(len(blob)))
	b = append(b, blob...)
	if dialect == Dialect311 {
		for (64+len(b))%8 != 0 {
			b = append(b, 0)
		}
		binary.LittleEndian.PutUint32(b[60:], uint32(64+len(b)))
		binary.LittleEndian.PutUint16(b[6:], 2)
		b = appendContext(b, 1, append([]byte{1, 0, 32, 0, 1, 0}, make([]byte, 32)...))
		b = appendContext(b, 2, []byte{1, 0, 2, 0})
	}
	return append(respHeader(CmdNegotiate, 0, msgID, 0, 0), b...)
}

func challengeMsg() []byte {
	av := func(id uint16, s string) []byte {
		v := ntlm.EncodeUTF16(s)
		b := make([]byte, 4+len(v))
		binary.LittleEndian.PutUint16(b, id)
		binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
		copy(b[4:], v)
		return b
	}
	var ti []byte
	ti = append(ti, av(ntlm.AvNbDomainName, "CORP")...)
	ti = append(ti, av(ntlm.AvNbComputerName, "FS01")...)
	ti = append(ti, av(ntlm.AvDNSDomainName, "corp.local")...)
	ti = append(ti, av(ntlm.AvDNSComputerName, "fs01.corp.local")...)
	ti = append(ti, 0, 0, 0, 0)
	b := make([]byte, 56)
	copy(b, ntlm.Signature)
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint32(b[20:], ntlm.FlagUnicode|ntlm.FlagTargetInfo|ntlm.FlagVersion)
	binary.LittleEndian.PutUint16(b[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(b[44:], 56)
	b[48], b[49] = 10, 0
	binary.LittleEndian.PutUint16(b[50:], 20348)
	b[55] = 15
	return append(b, ti...)
}

// fakeServer is a scripted SMB2 server: it answers each command with the handler output;
// the bool return closes the connection.
type fakeServer struct {
	t        *testing.T
	pipeData []byte
	overflow bool
	nullSess bool
	smb1Only bool
	denyTree bool
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	tr := NewTransport(c, 2*time.Second)
	sessLeg := 0
	for {
		raw, err := tr.Recv()
		if err != nil {
			return
		}
		if f.smb1Only {
			_ = tr.Send(append([]byte{0xff, 'S', 'M', 'B', 0x72}, make([]byte, 40)...))
			return
		}
		if !IsSMB2(raw) || len(raw) < 64 {
			return
		}
		cmd := binary.LittleEndian.Uint16(raw[12:])
		id := binary.LittleEndian.Uint64(raw[24:])
		var out []byte
		switch cmd {
		case CmdNegotiate:
			out = negotiateResponse(id, Dialect311, SigningEnabled)
		case CmdSessionSetup:
			sessLeg++
			if sessLeg == 1 {
				blob := ntlm.SPNEGOResponse(challengeMsg())
				body := make([]byte, 8)
				binary.LittleEndian.PutUint16(body, 9)
				binary.LittleEndian.PutUint16(body[4:], 72)
				binary.LittleEndian.PutUint16(body[6:], uint16(len(blob)))
				out = append(append(respHeader(cmd, StatusMoreProcessingRequired, id, 0, 0x1122), body...), blob...)
			} else {
				// check the second leg carries an anonymous AUTHENTICATE
				off := int(binary.LittleEndian.Uint16(raw[64+12:]))
				l := int(binary.LittleEndian.Uint16(raw[64+14:]))
				blob := raw[off : off+l]
				if !bytes.Contains(blob, ntlm.Signature) {
					f.t.Error("missing NTLM auth")
				}
				body := make([]byte, 8)
				binary.LittleEndian.PutUint16(body, 9)
				if f.nullSess {
					binary.LittleEndian.PutUint16(body[2:], SessionFlagNull)
					out = append(respHeader(cmd, 0, id, 0, 0x1122), body...)
				} else {
					out = append(respHeader(cmd, StatusAccessDenied, id, 0, 0x1122), 9, 0, 0, 0, 0, 0, 0, 0, 0)
				}
			}
		case CmdTreeConnect:
			if f.denyTree {
				out = append(respHeader(cmd, StatusAccessDenied, id, 0, 0x1122), 9, 0, 0, 0, 0, 0, 0, 0, 0)
				break
			}
			body := make([]byte, 16)
			binary.LittleEndian.PutUint16(body, 16)
			body[2] = 2
			binary.LittleEndian.PutUint32(body[12:], 0x1f01ff)
			out = append(respHeader(cmd, 0, id, 7, 0x1122), body...)
		case CmdCreate:
			body := make([]byte, 88)
			binary.LittleEndian.PutUint16(body, 89)
			copy(body[64:80], bytes.Repeat([]byte{0xab}, 16))
			out = append(respHeader(cmd, 0, id, 7, 0x1122), body...)
		case CmdIoctl:
			// interim async response first, to exercise STATUS_PENDING handling
			ih := respHeader(cmd, StatusPending, id, 0, 0x1122)
			binary.LittleEndian.PutUint32(ih[16:], 3)
			_ = tr.Send(append(ih, 9, 0, 0, 0, 0, 0, 0, 0, 0))
			data := f.pipeData
			status := uint32(0)
			if f.overflow {
				data = f.pipeData[:4]
				status = StatusBufferOverflow
			}
			body := make([]byte, 48)
			binary.LittleEndian.PutUint16(body, 49)
			binary.LittleEndian.PutUint32(body[32:], 64+48)
			binary.LittleEndian.PutUint32(body[36:], uint32(len(data)))
			out = append(append(respHeader(cmd, status, id, 7, 0x1122), body...), data...)
		case CmdRead:
			data := f.pipeData[4:]
			body := make([]byte, 16)
			binary.LittleEndian.PutUint16(body, 17)
			body[2] = 80
			binary.LittleEndian.PutUint32(body[4:], uint32(len(data)))
			out = append(append(respHeader(cmd, 0, id, 7, 0x1122), body...), data...)
		case CmdClose, CmdTreeDisconnect, CmdLogoff:
			body := make([]byte, 60)
			binary.LittleEndian.PutUint16(body, 60)
			out = append(respHeader(cmd, 0, id, 7, 0x1122), body...)
		default:
			return
		}
		if err := tr.Send(out); err != nil {
			return
		}
	}
}

func listen(t *testing.T, f *fakeServer) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func TestNegotiateAndChallenge(t *testing.T) {
	ip, port := listen(t, &fakeServer{t: t})
	c, err := Dial(context.Background(), ip, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ni, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	if ni.ServerGUID != "12345678-9abc-def0-0102-030405060708" {
		t.Fatalf("guid %q", ni.ServerGUID)
	}
	if ni.Dialect != Dialect311 || !ni.SigningEnabled || ni.SigningRequired {
		t.Fatalf("negotiate %+v", ni)
	}
	if !ni.SystemTime.Equal(time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)) {
		t.Fatal(ni.SystemTime)
	}
	if len(ni.Ciphers) != 1 || ni.Ciphers[0] != 2 {
		t.Fatalf("ciphers %v", ni.Ciphers)
	}
	ch, err := c.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	if ch.DNSComputer != "fs01.corp.local" || ch.Version == nil || ch.Version.Build != 20348 {
		t.Fatalf("challenge %+v", ch)
	}
}

func TestNullSessionPipe(t *testing.T) {
	payload := []byte("0123456789abcdef")
	for _, overflow := range []bool{false, true} {
		ip, port := listen(t, &fakeServer{t: t, nullSess: true, pipeData: payload, overflow: overflow})
		c, err := Dial(context.Background(), ip, port, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Negotiate(); err != nil {
			t.Fatal(err)
		}
		si, err := c.Login(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !si.Null {
			t.Fatal("expected null session")
		}
		tree, err := c.TreeConnect("IPC$")
		if err != nil {
			t.Fatal(err)
		}
		if tree.ID != 7 || tree.ShareType != 2 {
			t.Fatalf("tree %+v", tree)
		}
		fid, err := c.OpenPipe(tree, "srvsvc")
		if err != nil {
			t.Fatal(err)
		}
		out, err := c.Transceive(tree, fid, []byte("bind"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("overflow=%v got %q", overflow, out)
		}
		if err := c.CloseFile(tree, fid); err != nil {
			t.Fatal(err)
		}
		if err := c.TreeDisconnect(tree); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}

func TestLoginDenied(t *testing.T) {
	ip, port := listen(t, &fakeServer{t: t})
	c, err := Dial(context.Background(), ip, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Negotiate(); err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(&ntlm.Credentials{User: "guest"})
	if StatusOf(err) != StatusAccessDenied {
		t.Fatalf("err %v", err)
	}
}

func TestSMB1Only(t *testing.T) {
	ip, port := listen(t, &fakeServer{t: t, smb1Only: true})
	c, err := Dial(context.Background(), ip, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Negotiate(); !errors.Is(err, ErrSMB1Only) {
		t.Fatalf("err %v", err)
	}
}

func TestContextCancelClosesConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c) // never answers
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Dial(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := c.Negotiate(); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation not honoured")
	}
}

func TestParseNegotiateHostile(t *testing.T) {
	good := negotiateResponse(0, Dialect311, SigningEnabled|SigningRequired)
	ni, err := ParseNegotiateResponse(good)
	if err != nil || !ni.SigningRequired {
		t.Fatal(err)
	}
	for i := 0; i <= len(good); i++ {
		_, _ = ParseNegotiateResponse(good[:i])
	}
	seed := uint32(7)
	for n := 0; n < 3000; n++ {
		m := append([]byte(nil), good...)
		for k := 0; k < 3; k++ {
			seed = seed*1664525 + 1013904223
			m[4+int(seed>>4)%(len(m)-4)] = byte(seed >> 16)
		}
		_, _ = ParseNegotiateResponse(m)
	}
	for _, x := range [][]byte{nil, {0xfe}, []byte("\xfeSMB"), append([]byte("\xffSMB"), make([]byte, 60)...)} {
		if _, err := ParseNegotiateResponse(x); err == nil {
			t.Fatalf("accepted %x", x)
		}
	}
}

func TestReadBodyHostile(t *testing.T) {
	r := &Response{Raw: make([]byte, 80), Body: make([]byte, 16)}
	r.Body[2] = 200
	binary.LittleEndian.PutUint32(r.Body[4:], 10)
	if _, err := readBody(r); err == nil {
		t.Fatal("expected error")
	}
	binary.LittleEndian.PutUint32(r.Body[4:], 0xffffffff)
	r.Body[2] = 64
	if _, err := readBody(r); err == nil {
		t.Fatal("expected error")
	}
}

func TestNetBIOSName(t *testing.T) {
	n := EncodeNetBIOSName("*SMBSERVER", 0x20)
	if len(n) != 34 || n[0] != 32 || n[33] != 0 {
		t.Fatalf("%x", n)
	}
	// '*' = 0x2a -> "CK"
	if string(n[1:3]) != "CK" || string(n[31:33]) != "CA" {
		t.Fatalf("%s", n)
	}
}

func TestNetBIOSSession(t *testing.T) {
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
		h := make([]byte, 4)
		if _, err := io.ReadFull(c, h); err != nil || h[0] != 0x81 {
			return
		}
		_, _ = io.ReadFull(c, make([]byte, int(h[3])))
		_, _ = c.Write([]byte{0x83, 0, 0, 1, 0x82})
	}()
	tr := &Transport{}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tr.conn, tr.timeout = c, time.Second
	defer c.Close()
	if err := tr.netbiosSession(""); !errors.Is(err, ErrNetBIOSRefuse) {
		t.Fatalf("err %v", err)
	}
}

func TestFormatGUID(t *testing.T) {
	if FormatGUID(testGUID) != "12345678-9abc-def0-0102-030405060708" {
		t.Fatal(FormatGUID(testGUID))
	}
	if FormatGUID(testGUID[:3]) != "" {
		t.Fatal("short")
	}
}
