package identity

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

var (
	day1 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	day2 = day1.Add(24 * time.Hour)
)

func ev(kind model.EvidenceKind, value, source string, conf int, attrs ...string) model.IdentityEvidence {
	e := model.IdentityEvidence{Kind: kind, Value: value, Source: source, Confidence: conf}
	if len(attrs) > 0 {
		e.Attributes = map[string]string{}
		for i := 0; i+1 < len(attrs); i += 2 {
			e.Attributes[attrs[i]] = attrs[i+1]
		}
	}
	return e
}

func svc(port int, name string) model.Service {
	return model.Service{Port: port, Protocol: model.TCP, State: model.PortOpen, Name: name}
}

func winEvidence(name, guid string) []model.IdentityEvidence {
	return []model.IdentityEvidence{
		ev(model.EvSMBGUID, guid, "smb2/445", 95),
		ev(model.EvNetBIOSName, strings.ToUpper(name), "smb-ntlm/445", 80),
		ev(model.EvNetBIOSDomain, "CORP", "smb-ntlm/445", 80),
		ev(model.EvFQDN, name+".corp.local", "smb-ntlm/445", 90),
		ev(model.EvDomain, "corp.local", "smb-ntlm/445", 80),
		ev(model.EvOSVersion, "10.0.17763", "smb-ntlm/445", 60, "source", "ntlm", "os_name", "Windows Server 2019 / 10 1809"),
	}
}

func obsOf(network int64, ip, mac string, sameL2 bool, seen time.Time, evs []model.IdentityEvidence, svcs ...model.Service) model.HostObservation {
	return model.HostObservation{
		MissionID: 1, NetworkID: network, SameL2: sameL2,
		Host:     model.Host{IP: ip, MAC: mac, NetworkID: network},
		Services: svcs, Evidence: evs, SeenAt: seen,
	}
}

// resolveNew runs Resolve with no existing assets and assigns the given ID.
func resolveNew(t *testing.T, id int64, obs model.HostObservation) model.Asset {
	t.Helper()
	d := NewCorrelator().Resolve(nil, obs)
	if d.Matched {
		t.Fatalf("unexpected match on empty set")
	}
	d.Asset.ID = id
	return d.Asset
}

func TestResolveScenarios(t *testing.T) {
	c := NewCorrelator()
	srv := resolveNew(t, 10, obsOf(1, "10.0.0.5", "00:11:22:33:44:55", true, day1, winEvidence("srv01", "{AAAA-1111}"), svc(445, "microsoft-ds"), svc(3389, "ms-wbt-server")))
	linux := resolveNew(t, 11, obsOf(1, "10.0.0.6", "00:11:22:33:44:66", true, day1, []model.IdentityEvidence{
		ev(model.EvSSHHostKey, "SHA256:abc", "ssh/22", 90),
		ev(model.EvSSHHostKey, "SHA256:def", "ssh/22", 90),
		ev(model.EvReverseDNS, "web1.corp.local.", "rdns", 50),
	}, svc(22, "ssh"), svc(80, "http")))
	existing := []model.Asset{srv, linux}

	tests := []struct {
		name          string
		obs           model.HostObservation
		wantMatch     bool
		wantID        int64
		wantConflicts []int64
		check         func(t *testing.T, d model.AssetDecision)
	}{
		{
			name:      "same machine new IP next day",
			obs:       obsOf(1, "10.0.0.77", "00:11:22:33:44:55", true, day2, winEvidence("srv01", "aaaa-1111"), svc(445, "microsoft-ds")),
			wantMatch: true, wantID: 10,
			check: func(t *testing.T, d model.AssetDecision) {
				if len(d.Asset.IPs) != 2 {
					t.Fatalf("want 2 IPs, got %+v", d.Asset.IPs)
				}
				if !d.Asset.LastSeen.Equal(day2) || !d.Asset.FirstSeen.Equal(day1) {
					t.Fatalf("seen times wrong: %v %v", d.Asset.FirstSeen, d.Asset.LastSeen)
				}
				for _, k := range d.Asset.Keys {
					if k.Kind == model.EvSMBGUID && (!k.LastSeen.Equal(day2) || !k.FirstSeen.Equal(day1)) {
						t.Fatalf("key times not updated: %+v", k)
					}
				}
				if d.Score < 95 {
					t.Fatalf("score too low: %d", d.Score)
				}
			},
		},
		{
			name: "DHCP IP reuse by another machine",
			obs: obsOf(1, "10.0.0.5", "00:aa:bb:cc:dd:ee", true, day2, []model.IdentityEvidence{
				ev(model.EvSMBGUID, "bbbb-2222", "smb2/445", 95),
				ev(model.EvFQDN, "laptop7.corp.local", "smb-ntlm/445", 90),
			}, svc(445, "microsoft-ds")),
			wantMatch: false,
			check: func(t *testing.T, d model.AssetDecision) {
				if d.Asset.ID != 0 || d.Asset.Label != "laptop7.corp.local" {
					t.Fatalf("bad new asset: %+v", d.Asset)
				}
			},
		},
		{
			name: "multi-homed server seen on second VLAN",
			obs: obsOf(2, "192.168.50.5", "00:11:22:33:99:99", true, day2, []model.IdentityEvidence{
				ev(model.EvSMBGUID, "AAAA-1111", "smb2/445", 95),
			}, svc(445, "microsoft-ds")),
			wantMatch: true, wantID: 10,
			check: func(t *testing.T, d model.AssetDecision) {
				nets := map[int64]bool{}
				for _, ip := range d.Asset.IPs {
					nets[ip.NetworkID] = true
				}
				if !nets[1] || !nets[2] {
					t.Fatalf("want IPs on two networks: %+v", d.Asset.IPs)
				}
				macs := 0
				for _, k := range d.Asset.Keys {
					if k.Kind == model.EvMAC {
						macs++
					}
				}
				if macs != 2 {
					t.Fatalf("want both NIC MACs as keys, got %d", macs)
				}
			},
		},
		{
			name:      "MAC not usable across L3",
			obs:       obsOf(3, "172.16.0.9", "00:11:22:33:44:55", false, day2, nil),
			wantMatch: false,
			check: func(t *testing.T, d model.AssetDecision) {
				for _, k := range d.Asset.Keys {
					if k.Kind == model.EvMAC {
						t.Fatalf("router MAC must not be stored: %+v", k)
					}
				}
			},
		},
		{
			name: "nbstat MAC usable across L3",
			obs: obsOf(3, "172.16.0.9", "", false, day2, []model.IdentityEvidence{
				ev(model.EvMAC, "00-11-22-33-44-55", "nbstat/137", 85, "source", "nbstat"),
			}),
			wantMatch: true, wantID: 10,
		},
		{
			name: "reinstalled machine same hostname different GUID",
			obs: obsOf(1, "10.0.0.5", "00:11:22:33:44:55", false, day2, []model.IdentityEvidence{
				ev(model.EvSMBGUID, "cccc-3333", "smb2/445", 95),
				ev(model.EvFQDN, "srv01.corp.local", "smb-ntlm/445", 90),
				ev(model.EvNetBIOSName, "SRV01", "smb-ntlm/445", 80),
				ev(model.EvNetBIOSDomain, "CORP", "smb-ntlm/445", 80),
			}),
			wantMatch: false, wantConflicts: []int64{10},
		},
		{
			name: "ssh one shared key out of several",
			obs: obsOf(1, "10.0.0.66", "", false, day2, []model.IdentityEvidence{
				ev(model.EvSSHHostKey, "SHA256:def", "ssh/22", 90),
				ev(model.EvSSHHostKey, "SHA256:new", "ssh/22", 90),
			}),
			wantMatch: true, wantID: 11,
		},
		{
			name: "ssh all keys differ, same rdns",
			obs: obsOf(1, "10.0.0.6", "", false, day2, []model.IdentityEvidence{
				ev(model.EvSSHHostKey, "SHA256:zzz", "ssh/22", 90),
				ev(model.EvReverseDNS, "web1.corp.local", "rdns", 50),
			}),
			wantMatch: false, wantConflicts: []int64{11},
		},
		{
			name: "hostname alone is not enough",
			obs: obsOf(4, "10.9.9.9", "", false, day2, []model.IdentityEvidence{
				ev(model.EvHostname, "SRV01", "mdns/5353", 60),
			}),
			wantMatch: false, wantConflicts: []int64{10},
		},
		{
			name: "netbios name+domain pair matches",
			obs: obsOf(4, "10.9.9.9", "", false, day2, []model.IdentityEvidence{
				ev(model.EvNetBIOSName, "srv01", "nbstat/137", 80),
				ev(model.EvNetBIOSDomain, "corp", "nbstat/137", 80),
			}),
			wantMatch: true, wantID: 10,
		},
		{
			name:      "same IP no keys is only a hint",
			obs:       obsOf(1, "10.0.0.5", "", false, day2, nil),
			wantMatch: false, wantConflicts: []int64{10},
		},
		{
			name:      "random MAC alone is weak",
			obs:       obsOf(1, "10.0.0.200", "02:11:22:33:44:55", true, day2, nil),
			wantMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := c.Resolve(existing, tt.obs)
			if d.Matched != tt.wantMatch {
				t.Fatalf("matched=%v want %v (score %d, reasons %v)", d.Matched, tt.wantMatch, d.Score, d.Reasons)
			}
			if tt.wantMatch && d.Asset.ID != tt.wantID {
				t.Fatalf("asset id %d want %d", d.Asset.ID, tt.wantID)
			}
			if !tt.wantMatch && d.Asset.ID != 0 {
				t.Fatalf("new asset must have ID 0")
			}
			if tt.wantConflicts != nil && !reflect.DeepEqual(d.Conflicts, tt.wantConflicts) {
				t.Fatalf("conflicts %v want %v (reasons %v)", d.Conflicts, tt.wantConflicts, d.Reasons)
			}
			if len(d.Reasons) == 0 {
				t.Fatalf("reasons must not be empty")
			}
			if tt.check != nil {
				tt.check(t, d)
			}
			// Determinism.
			d2 := c.Resolve(existing, tt.obs)
			if !reflect.DeepEqual(d, d2) {
				t.Fatalf("non deterministic result")
			}
		})
	}
	// Input assets must not be mutated.
	if len(existing[0].IPs) != 1 {
		t.Fatalf("existing asset mutated: %+v", existing[0].IPs)
	}
}

func TestResolveTieLowestID(t *testing.T) {
	c := NewCorrelator()
	mk := func(id int64) model.Asset {
		return model.Asset{ID: id, MissionID: 1, Keys: []model.AssetKey{{Kind: model.EvFQDN, Value: "dup.corp.local", Confidence: 90}}}
	}
	existing := []model.Asset{mk(30), mk(7), mk(12)}
	obs := obsOf(1, "10.0.0.1", "", false, day1, []model.IdentityEvidence{ev(model.EvFQDN, "DUP.corp.local.", "rdns", 90)})
	d := c.Resolve(existing, obs)
	if !d.Matched || d.Asset.ID != 7 {
		t.Fatalf("want match on 7, got %+v", d)
	}
	if !reflect.DeepEqual(d.Conflicts, []int64{12, 30}) {
		t.Fatalf("conflicts %v", d.Conflicts)
	}
}

func TestResolveNewAssetFields(t *testing.T) {
	c := NewCorrelator()
	obs := obsOf(5, "10.1.1.1", "AA-BB-CC-00-11-22", true, day1, winEvidence("ws042", "g1"), svc(445, "microsoft-ds"), svc(3389, "ms-wbt-server"))
	obs.Evidence[5] = ev(model.EvOSVersion, "10.0.19045", "smb-ntlm/445", 60, "os_name", "Windows 10 22H2")
	d := c.Resolve(nil, obs)
	a := d.Asset
	if a.MissionID != 1 || a.Label != "ws042.corp.local" || a.Hostname != "ws042" || a.Domain != "corp.local" {
		t.Fatalf("bad asset: %+v", a)
	}
	if a.OS != "Windows 10 22H2" || a.Kind != model.AssetWorkstation {
		t.Fatalf("bad os/kind: %q %q", a.OS, a.Kind)
	}
	if !a.FirstSeen.Equal(day1) || !a.LastSeen.Equal(day1) {
		t.Fatalf("bad times")
	}
	var mac string
	for _, k := range a.Keys {
		if k.Kind == model.EvMAC {
			mac = k.Value
		}
	}
	if mac != "aa:bb:cc:00:11:22" {
		t.Fatalf("mac key %q", mac)
	}
	for i := 1; i < len(a.Keys); i++ {
		if a.Keys[i-1].Kind > a.Keys[i].Kind {
			t.Fatalf("keys not sorted")
		}
	}
}

func TestResolveKindNotDowngraded(t *testing.T) {
	c := NewCorrelator()
	a := model.Asset{ID: 1, Kind: model.AssetPrinter, Label: "p", Keys: []model.AssetKey{{Kind: model.EvSNMPEngineID, Value: "80001f8880aabbcc", Confidence: 95}}}
	obs := obsOf(1, "10.0.0.9", "", false, day2, []model.IdentityEvidence{ev(model.EvSNMPEngineID, "0x80:00:1F:88:80:AA:BB:CC", "snmp/161", 95)})
	d := c.Resolve([]model.Asset{a}, obs)
	if !d.Matched || d.Asset.Kind != model.AssetPrinter {
		t.Fatalf("got %+v", d)
	}
	if d.Asset.Label != "10.0.0.9" {
		t.Fatalf("label %q", d.Asset.Label)
	}
}

func TestLabelPriority(t *testing.T) {
	c := NewCorrelator()
	d := c.Resolve(nil, obsOf(1, "10.0.0.3", "", false, day1, []model.IdentityEvidence{ev(model.EvNetBIOSName, "PRN01", "nbstat/137", 80)}))
	if d.Asset.Label != "PRN01" {
		t.Fatalf("label %q", d.Asset.Label)
	}
	d = c.Resolve(nil, obsOf(1, "10.0.0.3", "", false, day1, nil))
	if d.Asset.Label != "10.0.0.3" || d.Asset.Kind != model.AssetUnknown {
		t.Fatalf("label %q kind %q", d.Asset.Label, d.Asset.Kind)
	}
}

func TestTLSSharedCertWeak(t *testing.T) {
	c := NewCorrelator()
	a := model.Asset{ID: 3, Keys: []model.AssetKey{{Kind: model.EvTLSCert, Value: "abcd", Confidence: 60}}}
	shared := obsOf(1, "10.0.0.1", "", false, day1, []model.IdentityEvidence{ev(model.EvTLSCert, "AB:CD", "tls/443", 20, "shared", "true")})
	if d := c.Resolve([]model.Asset{a}, shared); d.Matched {
		t.Fatalf("shared cert must not match alone")
	}
	unique := obsOf(1, "10.0.0.1", "", false, day1, []model.IdentityEvidence{
		ev(model.EvTLSCert, "abcd", "tls/443", 90),
		ev(model.EvHostname, "x", "rdns", 50),
	})
	a.Hostname = "x"
	if d := c.Resolve([]model.Asset{a}, unique); !d.Matched {
		t.Fatalf("unique cert + hostname should match: %+v", d)
	}
}

func TestCanonicalMAC(t *testing.T) {
	cases := map[string]string{
		"00:11:22:33:44:55": "00:11:22:33:44:55",
		"00-11-22-AA-BB-CC": "00:11:22:aa:bb:cc",
		"0011.22aa.bbcc":    "00:11:22:aa:bb:cc",
		"001122aabbcc":      "00:11:22:aa:bb:cc",
		"00:00:00:00:00:00": "",
		"ff:ff:ff:ff:ff:ff": "",
		"01:00:5e:00:00:01": "",
		"zz:11:22:33:44:55": "",
		"00:11:22":          "",
	}
	for in, want := range cases {
		if got := canonicalMAC(in); got != want {
			t.Errorf("canonicalMAC(%q)=%q want %q", in, got, want)
		}
	}
}

func FuzzResolve(f *testing.F) {
	f.Add("aa", "10.0.0.1", "00:11:22:33:44:55", true)
	f.Fuzz(func(t *testing.T, v, ip, mac string, l2 bool) {
		c := NewCorrelator()
		a := model.Asset{ID: 1, Keys: []model.AssetKey{{Kind: model.EvMAC, Value: mac}, {Kind: model.EvFQDN, Value: v}}}
		obs := obsOf(1, ip, mac, l2, day1, []model.IdentityEvidence{ev(model.EvFQDN, v, "x", 90), ev(model.EvMAC, v, "nbstat", 90, "source", "nbstat")})
		_ = c.Resolve([]model.Asset{a}, obs)
		_ = c.Enrich(obs.Host, nil, obs.Evidence)
	})
}
