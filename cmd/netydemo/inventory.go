package main

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/store"
)

// A machine to invent, with the services that make it look like what it is.
type demoHost struct {
	net      int // index into the networks slice
	last     int // last octet
	hostname string
	os       string
	vendor   string
	mac      string
	kind     model.AssetKind
	services []demoService
	findings []string // check ids
}

type demoService struct {
	port     int
	proto    model.Protocol
	name     string
	product  string
	version  string
	extra    string
	tunnel   string
	title    string
	server   string
	techs    []string
	banner   string
	sshAlgos bool
	tlsCN    string
	tlsSelf  bool
	tlsExp   bool
}

func seedInventory(ctx context.Context, st *store.Store, missionID int64, nets []demoNet, now time.Time, rng *rand.Rand) error {
	hosts := demoHosts()

	for _, h := range hosts {
		n := nets[h.net]
		ip := prefixHost(n.prefix, h.last)
		first := now.Add(-time.Duration(40+rng.Intn(20)) * time.Hour)
		last := now.Add(-time.Duration(rng.Intn(180)) * time.Minute)

		domain := ""
		if h.os != "" && strings.Contains(h.os, "Windows") {
			domain = "lumexa.lan"
		}
		host, err := st.UpsertHost(ctx, model.Host{
			MissionID: missionID, NetworkID: n.ID, IP: ip,
			MAC: h.mac, Vendor: h.vendor, Hostname: h.hostname, Domain: domain,
			OS: h.os, TTL: ttlFor(h.os), DiscoveredBy: []string{"arp", "tcp-syn:445"},
			FirstSeen: first, LastSeen: last, LastScanID: int64(h.net + 1),
		})
		if err != nil {
			return err
		}

		var svcIDs []int64
		for _, s := range h.services {
			sv := model.Service{
				MissionID: missionID, NetworkID: n.ID, HostID: host.ID, IP: ip,
				Port: s.port, Protocol: s.proto, State: model.PortOpen, Reason: "syn-ack",
				Name: s.name, Product: s.product, Version: s.version, ExtraInfo: s.extra,
				Tunnel: s.tunnel, Banner: s.banner, Confidence: 90, Method: "probe-match",
				FirstSeen: first, LastSeen: last, LastScanID: int64(h.net + 1),
			}
			if s.proto == model.UDP {
				sv.Reason = "udp-response"
			}
			if s.tlsCN != "" {
				sv.TLS = &model.TLSInfo{
					Version: "TLSv1.2", CipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					SubjectCN: s.tlsCN, Subject: "CN=" + s.tlsCN + ", O=Groupe Lumexa",
					SANs:   []string{s.tlsCN},
					Issuer: "CN=Lumexa Internal CA", Serial: "1b:3f:9c:04",
					NotBefore: now.AddDate(-2, 0, 0), NotAfter: now.AddDate(0, 0, 40),
					SelfSigned: s.tlsSelf, Expired: s.tlsExp,
					KeyAlgo: "RSA", KeyBits: 2048, SigAlgo: "SHA256-RSA",
					SHA256: fmt.Sprintf("%064x", rng.Int63()),
				}
				if s.tlsSelf {
					sv.TLS.Issuer = "CN=" + s.tlsCN
				}
				if s.tlsExp {
					sv.TLS.NotAfter = now.AddDate(0, -3, 0)
				}
			}
			if s.title != "" || s.server != "" {
				scheme := "http"
				if s.tunnel == "ssl" {
					scheme = "https"
				}
				sv.HTTP = &model.HTTPInfo{
					Scheme: scheme, URL: fmt.Sprintf("%s://%s:%d/", scheme, ip, s.port),
					StatusCode: 200, Title: s.title, Server: s.server,
					ContentType: "text/html; charset=utf-8", ContentLength: int64(1200 + rng.Intn(9000)),
					Technologies: s.techs,
					Headers: map[string]string{
						"Server":          s.server,
						"X-Frame-Options": "SAMEORIGIN",
					},
				}
				if strings.Contains(s.name, "winrm") || s.port == 5985 {
					sv.HTTP.AuthSchemes = []string{"Negotiate", "NTLM"}
				}
			}
			if s.sshAlgos {
				sv.SSH = &model.SSHInfo{
					Banner: s.banner,
					HostKeys: []model.SSHHostKey{
						{Type: "ssh-ed25519", SHA256: "SHA256:" + randB64(rng, 43)},
						{Type: "ssh-rsa", SHA256: "SHA256:" + randB64(rng, 43)},
					},
					KexAlgos: []string{"curve25519-sha256", "diffie-hellman-group14-sha1"},
					Ciphers:  []string{"chacha20-poly1305@openssh.com", "aes256-ctr"},
					MACs:     []string{"hmac-sha2-256", "hmac-sha1"},
					AuthMeth: []string{"publickey", "password"},
				}
			}
			saved, err := st.UpsertService(ctx, sv)
			if err != nil {
				return err
			}
			svcIDs = append(svcIDs, saved.ID)
		}

		// Findings, attached to the service they came from where there is one.
		for _, id := range h.findings {
			f := findingFor(id, ip)
			f.MissionID, f.NetworkID, f.HostID = missionID, n.ID, host.ID
			f.FirstSeen, f.LastSeen = first, last
			f.LastScanID = int64(h.net + 1)
			for i, s := range h.services {
				if s.port == f.Port && s.proto == f.Protocol && i < len(svcIDs) {
					f.ServiceID = svcIDs[i]
				}
			}
			if _, err := st.UpsertFinding(ctx, f); err != nil {
				return err
			}
		}

		// A stable identity for the machine.
		asset, err := st.SaveAsset(ctx, model.Asset{
			MissionID: missionID,
			Label:     labelFor(h, ip, domain),
			Hostname:  h.hostname, Domain: domain, OS: h.os, Kind: h.kind,
			Keys:      assetKeys(h, rng),
			IPs:       []model.AssetIP{{IP: ip, NetworkID: n.ID, FirstSeen: first, LastSeen: last}},
			FirstSeen: first, LastSeen: last,
		})
		if err != nil {
			return err
		}
		if err := st.SetHostAsset(ctx, host.ID, asset.ID); err != nil {
			return err
		}
	}
	return nil
}

func labelFor(h demoHost, ip, domain string) string {
	if h.hostname == "" {
		return ip
	}
	if domain != "" {
		return h.hostname + "." + domain
	}
	return h.hostname
}

func assetKeys(h demoHost, rng *rand.Rand) []model.AssetKey {
	keys := []model.AssetKey{{Kind: model.EvMAC, Value: h.mac, Source: "arp", Confidence: 80}}
	if h.hostname != "" {
		keys = append(keys, model.AssetKey{
			Kind: model.EvHostname, Value: h.hostname, Source: "nbns/137", Confidence: 40,
		})
	}
	if strings.Contains(h.os, "Windows") {
		keys = append(keys,
			model.AssetKey{Kind: model.EvSMBGUID, Value: randHexGUID(rng), Source: "smb-negotiate/445", Confidence: 95},
			model.AssetKey{Kind: model.EvNetBIOSDomain, Value: "LUMEXA", Source: "smb-ntlm/445", Confidence: 70},
		)
	}
	for _, s := range h.services {
		if s.sshAlgos {
			keys = append(keys, model.AssetKey{
				Kind: model.EvSSHHostKey, Value: "SHA256:" + randB64(rng, 43),
				Source: fmt.Sprintf("ssh/%d", s.port), Confidence: 90,
			})
			break
		}
	}
	return keys
}

func ttlFor(os string) int {
	switch {
	case strings.Contains(os, "Windows"):
		return 128
	case os == "":
		return 255
	default:
		return 64
	}
}

func prefixHost(prefix string, last int) string {
	base := strings.TrimSuffix(prefix, ".0/24")
	return fmt.Sprintf("%s.%d", base, last)
}

func randB64(rng *rand.Rand, n int) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rng.Intn(len(alpha))]
	}
	return string(b)
}

func randHexGUID(rng *rand.Rand) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		rng.Int31(), rng.Intn(65536), rng.Intn(65536), rng.Intn(65536), rng.Int63()&0xffffffffffff)
}
