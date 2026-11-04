package identity

import (
	"reflect"
	"testing"

	"github.com/vaadata/nety/internal/model"
)

func TestEnrich(t *testing.T) {
	c := NewCorrelator()
	tests := []struct {
		name  string
		host  model.Host
		svcs  []model.Service
		ev    []model.IdentityEvidence
		check func(t *testing.T, h model.Host)
	}{
		{
			name: "ntlm windows",
			host: model.Host{IP: "10.0.0.5"},
			ev:   winEvidence("srv01", "g"),
			check: func(t *testing.T, h model.Host) {
				if h.Hostname != "srv01" || h.Domain != "corp.local" || h.OS != "Windows Server 2019 / 10 1809" {
					t.Fatalf("got %+v", h)
				}
				if !reflect.DeepEqual(h.Hostnames, []string{"SRV01", "srv01.corp.local"}) {
					t.Fatalf("hostnames %v", h.Hostnames)
				}
			},
		},
		{
			name: "netbios only keeps case",
			host: model.Host{IP: "10.0.0.6"},
			ev: []model.IdentityEvidence{
				ev(model.EvNetBIOSName, "PC-042", "nbstat/137", 80),
				ev(model.EvNetBIOSDomain, "WORKGROUP", "nbstat/137", 80),
			},
			check: func(t *testing.T, h model.Host) {
				if h.Hostname != "PC-042" || h.Domain != "WORKGROUP" {
					t.Fatalf("got %+v", h)
				}
			},
		},
		{
			name: "smb1 native os",
			ev:   []model.IdentityEvidence{ev(model.EvOSVersion, "Windows Server 2003 3790 Service Pack 2", "smb1/445", 70, "source", "smb1")},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Windows Server 2003 3790 Service Pack 2" {
					t.Fatalf("os %q", h.OS)
				}
			},
		},
		{
			name: "snmp sysdescr",
			ev:   []model.IdentityEvidence{ev(model.EvSNMPSysName, "core-sw", "snmp/161", 60, "sysdescr", "Juniper Networks, Inc. ex4300 \r\n JUNOS 18.4")},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Juniper Networks, Inc. ex4300" || h.Hostname != "core-sw" {
					t.Fatalf("got %+v", h)
				}
			},
		},
		{
			name: "bare ntlm version",
			ev:   []model.IdentityEvidence{ev(model.EvOSVersion, "6.1.7601", "rdp-ntlm/3389", 60, "source", "ntlm")},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Windows (6.1.7601)" {
					t.Fatalf("os %q", h.OS)
				}
			},
		},
		{
			name: "service ostype majority",
			svcs: []model.Service{{OSType: "Linux"}, {OSType: "Linux"}, {OSType: "Unix"}},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Linux" {
					t.Fatalf("os %q", h.OS)
				}
			},
		},
		{
			name: "ssh banner distro",
			svcs: []model.Service{{Port: 22, SSH: &model.SSHInfo{Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"}}},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Linux (Ubuntu)" {
					t.Fatalf("os %q", h.OS)
				}
			},
		},
		{
			name: "debian suffix",
			svcs: []model.Service{{Port: 22, Banner: "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"}},
			check: func(t *testing.T, h model.Host) {
				if h.OS != "Linux (Debian)" {
					t.Fatalf("os %q", h.OS)
				}
			},
		},
		{
			name: "keeps existing when no evidence",
			host: model.Host{Hostname: "keep", Domain: "d", OS: "Linux", Vendor: "V", Hostnames: []string{"keep.d"}},
			check: func(t *testing.T, h model.Host) {
				if h.Hostname != "keep" || h.Domain != "d" || h.OS != "Linux" || h.Vendor != "V" {
					t.Fatalf("got %+v", h)
				}
				if !reflect.DeepEqual(h.Hostnames, []string{"keep", "keep.d"}) {
					t.Fatalf("hostnames %v", h.Hostnames)
				}
			},
		},
		{
			name: "vendor and rdns and mdns",
			host: model.Host{IP: "10.0.0.9"},
			ev: []model.IdentityEvidence{
				ev(model.EvVendor, "Apple, Inc.", "oui", 10),
				ev(model.EvMDNSName, "Johns-MacBook.local.", "mdns/5353", 60),
				ev(model.EvReverseDNS, "10-0-0-9.dhcp.corp.local.", "rdns", 30),
			},
			check: func(t *testing.T, h model.Host) {
				if h.Vendor != "Apple, Inc." || h.Hostname != "Johns-MacBook" {
					t.Fatalf("got %+v", h)
				}
				if len(h.Hostnames) != 3 {
					t.Fatalf("hostnames %v", h.Hostnames)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := c.Enrich(tt.host, tt.svcs, tt.ev)
			tt.check(t, h)
			if h2 := c.Enrich(tt.host, tt.svcs, tt.ev); !reflect.DeepEqual(h, h2) {
				t.Fatalf("non deterministic")
			}
		})
	}
}
