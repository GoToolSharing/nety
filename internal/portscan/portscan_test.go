package portscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestConnectScanLocal(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	// A port that is very likely closed: listen then close.
	l2, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedPort := uint16(l2.Addr().(*net.TCPAddr).Port)
	l2.Close()

	var mu sync.Mutex
	var got []engine.PortResult
	var lastDone, lastTotal int64
	err = New(quietLog()).Scan(context.Background(), engine.PortScanOptions{
		Hosts:    []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
		TCPPorts: []uint16{openPort, closedPort, openPort},
		Mode:     engine.ModeConnect,
		Timeout:  time.Second,
		Progress: func(d, tot int64) { mu.Lock(); lastDone, lastTotal = d, tot; mu.Unlock() },
	}, func(r engine.PortResult) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != openPort || got[0].Proto != model.TCP || got[0].State != model.PortOpen {
		t.Fatalf("results %+v", got)
	}
	if lastDone != lastTotal || lastTotal != 2 {
		t.Fatalf("progress %d/%d", lastDone, lastTotal)
	}
}

func TestConnectScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New(quietLog()).Scan(ctx, engine.PortScanOptions{
		Hosts:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		TCPPorts: []uint16{1, 2, 3},
		Mode:     engine.ModeConnect,
	}, func(engine.PortResult) {})
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestUDPScanLocal(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	var got []engine.PortResult
	var mu sync.Mutex
	err = New(quietLog()).Scan(context.Background(), engine.PortScanOptions{
		Hosts:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		UDPPorts: []uint16{port, 9},
		Timeout:  300 * time.Millisecond,
		Retries:  -1,
	}, func(r engine.PortResult) { mu.Lock(); got = append(got, r); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != port || got[0].Proto != model.UDP || got[0].Reason != "udp-response" {
		t.Fatalf("results %+v", got)
	}
}

func TestPayloads(t *testing.T) {
	snmp := UDPPayloads(161)
	if len(snmp) != 2 {
		t.Fatal("snmp payload count")
	}
	for _, p := range snmp {
		if p[0] != 0x30 || int(p[1]) != len(p)-2 || !bytes.Contains(p, []byte("public")) {
			t.Fatalf("bad snmp %x", p)
		}
	}
	ike := UDPPayloads(500)[0]
	if len(ike) != 84 || binary.BigEndian.Uint32(ike[24:]) != 84 || ike[16] != 1 || ike[17] != 0x10 {
		t.Fatalf("ike %d % x", len(ike), ike[:28])
	}
	krb := UDPPayloads(88)[0]
	if krb[0] != 0x6a || int(krb[1])+2 != len(krb) && !(krb[1] == 0x81 && int(krb[2])+3 == len(krb)) {
		t.Fatalf("krb % x", krb)
	}
	nb := UDPPayloads(137)[0]
	if len(nb) != 50 || nb[len(nb)-4] != 0x00 || nb[len(nb)-3] != 0x21 {
		t.Fatalf("nbstat %d % x", len(nb), nb)
	}
	dns := UDPPayloads(53)[0]
	if !bytes.Contains(dns, []byte("\x07version\x04bind\x00\x00\x10\x00\x03")) {
		t.Fatalf("dns % x", dns)
	}
	ldap := UDPPayloads(389)[0]
	if ldap[0] != 0x30 || int(ldap[1]) != len(ldap)-2 {
		t.Fatalf("cldap % x", ldap)
	}
	if len(UDPPayloads(123)[0]) != 48 || len(UDPPayloads(40000)) != 1 || len(UDPPayloads(40000)[0]) != 0 {
		t.Fatal("ntp/generic")
	}
	if HasUDPPayload(40000) || !HasUDPPayload(5060) {
		t.Fatal("HasUDPPayload")
	}
}

func TestDoneSets(t *testing.T) {
	for _, d := range []doneSet{newDoneSet(1000), &mapDone{m: map[uint64]struct{}{}}} {
		if d.has(5) || d.testAndSet(5) || !d.testAndSet(5) || !d.has(5) || d.has(6) {
			t.Fatalf("%T semantics", d)
		}
	}
}

func TestRetries(t *testing.T) {
	if retries(0, 1) != 1 || retries(-1, 1) != 0 || retries(3, 1) != 3 || retries(50, 1) != 10 {
		t.Fatal("retries")
	}
}

func TestModeErrors(t *testing.T) {
	err := New(quietLog()).Scan(context.Background(), engine.PortScanOptions{
		Hosts: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, TCPPorts: []uint16{1}, Mode: "bogus",
	}, func(engine.PortResult) {})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}
