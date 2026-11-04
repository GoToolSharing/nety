package export

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/config"
	"github.com/GoToolSharing/nety/internal/model"
)

// Nmap XML output. The schema is the one every downstream tool already parses
// (Metasploit db_import, Faraday, DefectDojo, python-libnmap...), so a NETY
// scan drops straight into an existing workflow.

type nmapRun struct {
	XMLName          xml.Name   `xml:"nmaprun"`
	Scanner          string     `xml:"scanner,attr"`
	Args             string     `xml:"args,attr"`
	Start            int64      `xml:"start,attr"`
	StartStr         string     `xml:"startstr,attr"`
	Version          string     `xml:"version,attr"`
	XMLOutputVersion string     `xml:"xmloutputversion,attr"`
	ScanInfo         nmapScan   `xml:"scaninfo"`
	Verbose          nmapLevel  `xml:"verbose"`
	Debugging        nmapLevel  `xml:"debugging"`
	Hosts            []nmapHost `xml:"host"`
	RunStats         nmapStats  `xml:"runstats"`
}

type nmapScan struct {
	Type     string `xml:"type,attr"`
	Protocol string `xml:"protocol,attr"`
	NumServ  int    `xml:"numservices,attr"`
	Services string `xml:"services,attr"`
}

type nmapLevel struct {
	Level int `xml:"level,attr"`
}

type nmapHost struct {
	StartTime  int64           `xml:"starttime,attr,omitempty"`
	EndTime    int64           `xml:"endtime,attr,omitempty"`
	Status     nmapStatus      `xml:"status"`
	Addresses  []nmapAddress   `xml:"address"`
	Hostnames  nmapHostnames   `xml:"hostnames"`
	Ports      nmapPorts       `xml:"ports"`
	OS         *nmapOS         `xml:"os,omitempty"`
	HostScript *nmapHostScript `xml:"hostscript,omitempty"`
}

type nmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapPortSt   `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script,omitempty"`
}

type nmapPortSt struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

type nmapService struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	Tunnel    string   `xml:"tunnel,attr,omitempty"`
	OSType    string   `xml:"ostype,attr,omitempty"`
	Method    string   `xml:"method,attr"`
	Conf      int      `xml:"conf,attr"`
	CPEs      []string `xml:"cpe,omitempty"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapHostScript struct {
	Scripts []nmapScript `xml:"script"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

type nmapStats struct {
	Finished nmapFinished `xml:"finished"`
	Hosts    nmapHostStat `xml:"hosts"`
}

type nmapFinished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type nmapHostStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

func writeNmapXML(w io.Writer, d model.MissionData) error {
	now := time.Now().UTC()
	run := nmapRun{
		Scanner:          "nety",
		Args:             fmt.Sprintf("nety export --mission %q", d.Mission.Name),
		Start:            now.Unix(),
		StartStr:         now.Format(time.ANSIC),
		Version:          config.Version,
		XMLOutputVersion: "1.05",
		ScanInfo: nmapScan{
			Type: "syn", Protocol: "tcp",
			NumServ: countPorts(d), Services: portSummary(d),
		},
	}

	byHost := servicesByHost(d)
	names := networkNames(d)
	findingsByHost := map[int64][]model.Finding{}
	for _, f := range d.Findings {
		findingsByHost[f.HostID] = append(findingsByHost[f.HostID], f)
	}

	for _, h := range d.Hosts {
		nh := nmapHost{
			Status: nmapStatus{State: "up", Reason: reasonOf(h)},
			Addresses: []nmapAddress{
				{Addr: h.IP, AddrType: addrType(h.IP)},
			},
		}
		if h.MAC != "" {
			nh.Addresses = append(nh.Addresses, nmapAddress{
				Addr: strings.ToUpper(h.MAC), AddrType: "mac", Vendor: h.Vendor,
			})
		}
		for _, name := range hostnamesOf(h) {
			nh.Hostnames.Hostnames = append(nh.Hostnames.Hostnames,
				nmapHostname{Name: name, Type: "PTR"})
		}
		if h.OS != "" {
			nh.OS = &nmapOS{OSMatches: []nmapOSMatch{{Name: h.OS, Accuracy: 90}}}
		}
		if !h.FirstSeen.IsZero() {
			nh.StartTime = h.FirstSeen.Unix()
		}
		if !h.LastSeen.IsZero() {
			nh.EndTime = h.LastSeen.Unix()
		}

		for _, s := range byHost[h.ID] {
			np := nmapPort{
				Protocol: string(s.Protocol),
				PortID:   s.Port,
				State: nmapPortSt{
					State:     string(s.State),
					Reason:    firstNonEmpty(s.Reason, "syn-ack"),
					ReasonTTL: h.TTL,
				},
				Service: nmapService{
					Name:      firstNonEmpty(s.Name, "unknown"),
					Product:   s.Product,
					Version:   s.Version,
					ExtraInfo: s.ExtraInfo,
					Tunnel:    s.Tunnel,
					OSType:    s.OSType,
					Method:    methodFor(s),
					Conf:      confFor(s),
					CPEs:      s.CPEs,
				},
			}
			np.Scripts = append(np.Scripts, serviceScripts(s)...)
			for _, f := range findingsByHost[h.ID] {
				if f.Port == s.Port && f.Protocol == s.Protocol {
					np.Scripts = append(np.Scripts, nmapScript{
						ID:     "nety-" + f.CheckID,
						Output: fmt.Sprintf("[%s] %s - %s", strings.ToUpper(string(f.Severity)), f.Title, oneLine(f.Evidence, 400)),
					})
				}
			}
			nh.Ports.Ports = append(nh.Ports.Ports, np)
		}

		var hostScripts []nmapScript
		if label := netName(names, h.NetworkID); label != "" {
			hostScripts = append(hostScripts, nmapScript{ID: "nety-network", Output: label})
		}
		for _, f := range findingsByHost[h.ID] {
			if f.Port == 0 {
				hostScripts = append(hostScripts, nmapScript{
					ID:     "nety-" + f.CheckID,
					Output: fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Title),
				})
			}
		}
		if len(hostScripts) > 0 {
			nh.HostScript = &nmapHostScript{Scripts: hostScripts}
		}
		run.Hosts = append(run.Hosts, nh)
	}

	run.RunStats = nmapStats{
		Finished: nmapFinished{
			Time: now.Unix(), TimeStr: now.Format(time.ANSIC), Elapsed: "0.00",
			Summary: fmt.Sprintf("NETY done; %d hosts up", len(d.Hosts)),
			Exit:    "success",
		},
		Hosts: nmapHostStat{Up: len(d.Hosts), Total: len(d.Hosts)},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	if _, err := io.WriteString(w,
		"<!DOCTYPE nmaprun>\n<?xml-stylesheet href=\"file:///usr/local/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n"); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return fmt.Errorf("export nmap xml: %w", err)
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// writeGnmap renders the greppable format, still the quickest way to grep an
// internal scan from a shell.
func writeGnmap(w io.Writer, d model.MissionData) error {
	now := time.Now().UTC()
	if _, err := fmt.Fprintf(w, "# NETY %s scan initiated %s as: nety export --mission %q\n",
		config.Version, now.Format(time.ANSIC), d.Mission.Name); err != nil {
		return err
	}
	byHost := servicesByHost(d)
	for _, h := range d.Hosts {
		name := ""
		if hn := hostLabel(h); hn != h.IP {
			name = " (" + hn + ")"
		}
		if _, err := fmt.Fprintf(w, "Host: %s%s\tStatus: Up\n", h.IP, name); err != nil {
			return err
		}
		services := byHost[h.ID]
		if len(services) == 0 {
			continue
		}
		parts := make([]string, 0, len(services))
		for _, s := range services {
			// port/state/proto/owner/service/rpc_info/version/
			parts = append(parts, fmt.Sprintf("%d/%s/%s//%s//%s/",
				s.Port, shortState(s.State), s.Protocol,
				escapeGnmap(firstNonEmpty(s.Name, "unknown")),
				escapeGnmap(serviceLabel(s))))
		}
		if _, err := fmt.Fprintf(w, "Host: %s%s\tPorts: %s\n", h.IP, name, strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "# NETY done at %s -- %d IP addresses\n",
		now.Format(time.ANSIC), len(d.Hosts))
	return err
}

// ---------------------------------------------------------------------------

func addrType(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	return "ipv4"
}

func reasonOf(h model.Host) string {
	if len(h.DiscoveredBy) > 0 {
		return h.DiscoveredBy[0]
	}
	return "user-set"
}

func hostnamesOf(h model.Host) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append([]string{h.Hostname}, h.Hostnames...) {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func methodFor(s model.Service) string {
	if s.Confidence >= 50 && s.Method != "port-table" {
		return "probed"
	}
	return "table"
}

func confFor(s model.Service) int {
	// nmap uses 1..10.
	c := s.Confidence / 10
	if c < 1 {
		c = 3
	}
	if c > 10 {
		c = 10
	}
	return c
}

func serviceScripts(s model.Service) []nmapScript {
	var out []nmapScript
	if s.TLS != nil {
		out = append(out, nmapScript{
			ID: "ssl-cert",
			Output: fmt.Sprintf("Subject: %s | Issuer: %s | Not valid after: %s | SHA-256: %s",
				firstNonEmpty(s.TLS.SubjectCN, s.TLS.Subject), s.TLS.Issuer,
				ts(s.TLS.NotAfter), s.TLS.SHA256),
		})
		if len(s.TLS.SANs) > 0 {
			out = append(out, nmapScript{ID: "ssl-cert-san", Output: strings.Join(s.TLS.SANs, ", ")})
		}
	}
	if s.HTTP != nil {
		out = append(out, nmapScript{
			ID:     "http-title",
			Output: fmt.Sprintf("%s (status %d)", firstNonEmpty(s.HTTP.Title, "(no title)"), s.HTTP.StatusCode),
		})
		if len(s.HTTP.Technologies) > 0 {
			out = append(out, nmapScript{ID: "http-tech", Output: strings.Join(s.HTTP.Technologies, ", ")})
		}
	}
	if s.SSH != nil && len(s.SSH.HostKeys) > 0 {
		var keys []string
		for _, k := range s.SSH.HostKeys {
			keys = append(keys, k.Type+" "+k.SHA256)
		}
		out = append(out, nmapScript{ID: "ssh-hostkey", Output: strings.Join(keys, "; ")})
	}
	if s.Banner != "" {
		out = append(out, nmapScript{ID: "banner", Output: oneLine(s.Banner, 300)})
	}
	return out
}

func shortState(s model.PortState) string {
	switch s {
	case model.PortOpen:
		return "open"
	case model.PortClosed:
		return "closed"
	case model.PortOpenFiltered:
		return "open|filtered"
	default:
		return "filtered"
	}
}

func escapeGnmap(s string) string {
	s = strings.ReplaceAll(s, ",", ";")
	s = strings.ReplaceAll(s, "/", "|")
	return oneLine(s, 120)
}

func countPorts(d model.MissionData) int {
	seen := map[int]bool{}
	for _, s := range d.Services {
		seen[s.Port] = true
	}
	return len(seen)
}

func portSummary(d model.MissionData) string {
	seen := map[int]bool{}
	var list []int
	for _, s := range d.Services {
		if !seen[s.Port] {
			seen[s.Port] = true
			list = append(list, s.Port)
		}
	}
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, itoa(p))
	}
	return strings.Join(parts, ",")
}
