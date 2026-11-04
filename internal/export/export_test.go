package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/model"
)

func sampleData() model.MissionData {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	return model.MissionData{
		Mission: model.Mission{ID: 1, Name: "Revue interne", Client: "ACME & Co"},
		Networks: []model.Network{
			{ID: 1, Name: "Bureaux", VLANID: 10, Prefixes: []string{"10.10.0.0/24"}, Gateway: "10.10.0.1",
				L2: model.L2Info{DTPSeen: true, DTPMode: "desirable", NativeVLAN: 1,
					Neighbors: []model.L2Neighbor{{Protocol: "cdp", DeviceID: "SW-CORE-01", PortID: "Gi1/0/12", Platform: "cisco WS-C2960X"}}}},
			{ID: 2, Name: "Serveurs", VLANID: 20, Prefixes: []string{"10.20.0.0/24"}, Gateway: "10.20.0.1"},
		},
		Hosts: []model.Host{
			{ID: 10, MissionID: 1, NetworkID: 1, IP: "10.10.0.50", Hostname: "poste-01",
				Domain: "corp.local", MAC: "00:0c:29:aa:bb:cc", Vendor: "VMware, Inc.",
				OS: "Windows 10", TTL: 128, AssetID: 100, DiscoveredBy: []string{"arp"},
				FirstSeen: now, LastSeen: now},
			{ID: 11, MissionID: 1, NetworkID: 2, IP: "10.20.0.8", Hostname: "srv-web",
				OS: "Linux", TTL: 64, FirstSeen: now, LastSeen: now},
		},
		Services: []model.Service{
			{ID: 20, MissionID: 1, NetworkID: 1, HostID: 10, IP: "10.10.0.50", Port: 445,
				Protocol: model.TCP, State: model.PortOpen, Reason: "syn-ack",
				Name: "microsoft-ds", Product: "Windows SMB", Confidence: 90, Method: "probe-match",
				FirstSeen: now, LastSeen: now},
			{ID: 21, MissionID: 1, NetworkID: 2, HostID: 11, IP: "10.20.0.8", Port: 443,
				Protocol: model.TCP, State: model.PortOpen, Name: "http", Product: "nginx",
				Version: "1.24.0", Tunnel: "ssl", Confidence: 90, Method: "probe-match",
				Banner: "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
				TLS: &model.TLSInfo{Version: "TLS1.3", SubjectCN: "srv-web.corp.local",
					Issuer: "Internal CA", NotAfter: now.AddDate(1, 0, 0), SHA256: "ab12cd"},
				HTTP: &model.HTTPInfo{StatusCode: 200, Title: "Intranet ACME",
					Server: "nginx", Technologies: []string{"nginx", "PHP"}},
				FirstSeen: now, LastSeen: now},
			{ID: 22, MissionID: 1, NetworkID: 2, HostID: 11, IP: "10.20.0.8", Port: 161,
				Protocol: model.UDP, State: model.PortOpen, Name: "snmp", Confidence: 50,
				FirstSeen: now, LastSeen: now},
		},
		Assets: []model.Asset{
			{ID: 100, MissionID: 1, Label: "poste-01.corp.local", Hostname: "poste-01",
				Domain: "corp.local", OS: "Windows 10", Kind: model.AssetWorkstation,
				Keys:      []model.AssetKey{{Kind: model.EvSMBGUID, Value: "guid-1", Confidence: 95}},
				IPs:       []model.AssetIP{{IP: "10.10.0.50", NetworkID: 1}},
				FirstSeen: now, LastSeen: now},
		},
		Findings: []model.Finding{
			{ID: 30, MissionID: 1, NetworkID: 1, HostID: 10, ServiceID: 20, IP: "10.10.0.50",
				Port: 445, Protocol: model.TCP, CheckID: "smb-signing-not-required",
				Title: "SMB signing not required", Severity: model.SevMedium,
				Description: "The server accepts unsigned SMB sessions.",
				Evidence:    "negotiate: signing enabled=true required=false",
				Remediation: "Require SMB signing by GPO.",
				References:  []string{"https://learn.microsoft.com/"},
				FirstSeen:   now, LastSeen: now},
			{ID: 31, MissionID: 1, NetworkID: 2, HostID: 11, IP: "10.20.0.8",
				CheckID: "tls-expired", Title: "Expired certificate", Severity: model.SevLow,
				FirstSeen: now, LastSeen: now},
		},
		Reach: []model.ReachResult{
			{ID: 40, MissionID: 1, SourceNetworkID: 1, TargetNetworkID: 2, TargetServiceID: 21,
				IP: "10.20.0.8", Port: 443, Protocol: model.TCP, Technique: model.TechDirect,
				Status: model.ReachOpen, RTTMs: 1.25, TestedAt: now},
			{ID: 41, MissionID: 1, SourceNetworkID: 1, TargetNetworkID: 2, TargetServiceID: 22,
				IP: "10.20.0.8", Port: 161, Protocol: model.UDP, Technique: model.TechSrcPort53,
				Status: model.ReachFiltered, TestedAt: now},
		},
		Matrix: []model.MatrixCell{
			{SourceNetworkID: 1, TargetNetworkID: 2, Tested: 2, Reachable: 1, Filtered: 1,
				ByTechnique: map[string]int{model.TechDirect: 1}},
		},
		ExportedAt: now,
		ExportedBy: "martina",
	}
}

func exportTo(t *testing.T, format string, networkID int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := New().Export(&buf, format, sampleData(), networkID); err != nil {
		t.Fatalf("export %s: %v", format, err)
	}
	if buf.Len() == 0 {
		t.Fatalf("export %s produced no output", format)
	}
	return buf.Bytes()
}

func TestEveryFormatProducesOutput(t *testing.T) {
	for _, f := range New().Formats() {
		out := exportTo(t, f.ID, 0)
		if len(out) < 20 {
			t.Fatalf("format %s produced a suspiciously small output (%d bytes)", f.ID, len(out))
		}
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	var buf bytes.Buffer
	if err := New().Export(&buf, "does-not-exist", sampleData(), 0); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var back model.MissionData
	if err := json.Unmarshal(exportTo(t, "json", 0), &back); err != nil {
		t.Fatalf("the JSON export must be valid JSON: %v", err)
	}
	if back.Mission.Name != "Revue interne" || len(back.Services) != 3 || len(back.Assets) != 1 {
		t.Fatalf("round trip lost data: %+v", back.Mission)
	}
	if back.Services[0].TLS != nil && back.Services[1].TLS == nil {
		t.Fatal("TLS details were lost")
	}
}

func TestCSVStructure(t *testing.T) {
	raw := exportTo(t, "csv-services", 0)
	// The BOM lets Excel read UTF-8; strip it before parsing.
	body := bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(rows) != 4 { // header + 3 services
		t.Fatalf("expected 4 rows, got %d", len(rows))
	}
	header := rows[0]
	if header[0] != "network" || header[3] != "port" {
		t.Fatalf("unexpected header: %v", header)
	}
	for _, r := range rows[1:] {
		if len(r) != len(header) {
			t.Fatalf("row has %d fields, header has %d", len(r), len(header))
		}
	}
}

func TestCSVFindingsOrderedBySeverity(t *testing.T) {
	body := bytes.TrimPrefix(exportTo(t, "csv-findings", 0), []byte{0xEF, 0xBB, 0xBF})
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[1][0] != "medium" || rows[2][0] != "low" {
		t.Fatalf("findings must come out worst-first, got %s then %s", rows[1][0], rows[2][0])
	}
}

func TestNmapXMLIsWellFormed(t *testing.T) {
	out := exportTo(t, "nmap-xml", 0)
	var run struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Addresses []struct {
				Addr     string `xml:"addr,attr"`
				AddrType string `xml:"addrtype,attr"`
			} `xml:"address"`
			Ports struct {
				Ports []struct {
					PortID  int    `xml:"portid,attr"`
					Proto   string `xml:"protocol,attr"`
					Service struct {
						Name    string `xml:"name,attr"`
						Product string `xml:"product,attr"`
					} `xml:"service"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(out, &run); err != nil {
		t.Fatalf("nmap XML is not well formed: %v", err)
	}
	if len(run.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(run.Hosts))
	}
	var found bool
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.PortID == 443 && p.Service.Product == "nginx" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the fingerprinted service is missing from the XML")
	}
	if !bytes.Contains(out, []byte("<!DOCTYPE nmaprun>")) {
		t.Fatal("the nmap doctype is expected by some parsers")
	}
}

func TestGnmapFormat(t *testing.T) {
	out := string(exportTo(t, "gnmap", 0))
	if !strings.Contains(out, "Host: 10.10.0.50 (poste-01.corp.local)\tStatus: Up") {
		t.Fatalf("missing status line:\n%s", out)
	}
	if !strings.Contains(out, "445/open/tcp//microsoft-ds//Windows SMB/") {
		t.Fatalf("missing port line:\n%s", out)
	}
}

func TestTargetsList(t *testing.T) {
	out := string(exportTo(t, "targets-txt", 0))
	for _, want := range []string{"10.10.0.50:445", "10.20.0.8:443", "10.20.0.8:161/udp"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMarkdownHighlightsSegmentation(t *testing.T) {
	out := string(exportTo(t, "markdown", 0))
	for _, want := range []string{
		"# Internal network review",
		"ACME & Co",
		"## Segmentation matrix",
		"Flows that crossed the segmentation",
		"`direct`",
		"SMB signing not required",
		"negotiates trunking",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown is missing %q", want)
		}
	}
}

func TestHTMLIsEscapedAndComplete(t *testing.T) {
	out := string(exportTo(t, "html", 0))
	if !strings.Contains(out, "<!doctype html>") || !strings.Contains(out, "</html>") {
		t.Fatal("HTML document is truncated")
	}
	// The client name contains an ampersand: it must be escaped, never raw.
	if strings.Contains(out, "ACME & Co") {
		t.Fatal("HTML output is not escaped")
	}
	if !strings.Contains(out, "ACME &amp; Co") {
		t.Fatal("client name missing from the HTML report")
	}
	for _, want := range []string{"Segmentation matrix", "sev-medium", "negotiates trunking"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML is missing %q", want)
		}
	}
}

func TestXLSXIsAZipWorkbook(t *testing.T) {
	out := exportTo(t, "xlsx", 0)
	if !bytes.HasPrefix(out, []byte("PK")) {
		t.Fatal("xlsx must be a zip container")
	}
	if len(out) < 4000 {
		t.Fatalf("xlsx looks empty (%d bytes)", len(out))
	}
}

func TestNetworkFilterRestrictsEverything(t *testing.T) {
	body := bytes.TrimPrefix(exportTo(t, "csv-hosts", 2), []byte{0xEF, 0xBB, 0xBF})
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected only the hosts of network 2, got %d rows", len(rows)-1)
	}
	if rows[1][2] != "10.20.0.8" {
		t.Fatalf("wrong host kept: %v", rows[1])
	}
}

func TestFilenameIsSafe(t *testing.T) {
	name := Filename(sampleData(), "csv-services", 0)
	if !strings.HasPrefix(name, "nety-revue-interne-csv-services-") || !strings.HasSuffix(name, ".csv") {
		t.Fatalf("unexpected filename %q", name)
	}
	if strings.ContainsAny(name, `/\ :`) {
		t.Fatalf("filename must be path-safe, got %q", name)
	}
	withNet := Filename(sampleData(), "json", 1)
	if !strings.Contains(withNet, "bureaux") {
		t.Fatalf("per-network export should name the network: %q", withNet)
	}
}

func TestIPOrdering(t *testing.T) {
	if !ipLess("10.0.0.2", "10.0.0.10") {
		t.Fatal("IPv4 must sort numerically, not lexicographically")
	}
	if ipLess("10.0.0.10", "10.0.0.2") {
		t.Fatal("ordering is reversed")
	}
	if !ipLess("10.0.0.1", "not-an-ip") {
		t.Fatal("malformed values must sort last-ish without panicking")
	}
}
