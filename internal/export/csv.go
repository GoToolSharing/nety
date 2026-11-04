package export

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

func writeHostsCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)
	assets := assetIndex(d)

	if err := cw.Write([]string{
		"network", "vlan_id", "ip", "hostname", "domain", "mac", "vendor", "os",
		"ttl", "asset", "open_ports", "discovered_by", "first_seen", "last_seen",
	}); err != nil {
		return err
	}
	portsByHost := openPortsByHost(d)
	vlan := vlanByNetwork(d)
	for _, h := range d.Hosts {
		if err := cw.Write([]string{
			netName(names, h.NetworkID),
			itoa(vlan[h.NetworkID]),
			h.IP, h.Hostname, h.Domain, h.MAC, h.Vendor, h.OS,
			itoa(h.TTL),
			assets[h.AssetID],
			portsByHost[h.ID],
			strings.Join(h.DiscoveredBy, " "),
			ts(h.FirstSeen), ts(h.LastSeen),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func writeServicesCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)
	hosts := hostIndex(d)

	// The triage columns come first after the identity of the service: this
	// sheet is what gets pasted into the client's tracking spreadsheet, and
	// "what is left to test" is the column people sort on.
	if err := cw.Write([]string{
		"network", "ip", "hostname", "port", "protocol", "state", "service",
		"triage_status", "triage_note", "triage_by", "triage_at",
		"product", "version", "extra_info", "tunnel", "os_type", "cpe",
		"http_status", "http_title", "http_server", "tls_subject", "tls_issuer",
		"tls_not_after", "tls_sha256", "ssh_hostkey", "banner", "confidence",
		"method", "first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, s := range d.Services {
		h := hosts[s.HostID]
		var httpStatus, httpTitle, httpServer string
		if s.HTTP != nil {
			httpStatus = itoa(s.HTTP.StatusCode)
			httpTitle = s.HTTP.Title
			httpServer = s.HTTP.Server
		}
		var tlsSubject, tlsIssuer, tlsExpiry, tlsFP string
		if s.TLS != nil {
			tlsSubject = firstNonEmpty(s.TLS.SubjectCN, s.TLS.Subject)
			tlsIssuer = s.TLS.Issuer
			tlsExpiry = ts(s.TLS.NotAfter)
			tlsFP = s.TLS.SHA256
		}
		var sshKeys []string
		if s.SSH != nil {
			for _, k := range s.SSH.HostKeys {
				sshKeys = append(sshKeys, k.Type+":"+k.SHA256)
			}
		}
		if err := cw.Write([]string{
			netName(names, s.NetworkID),
			s.IP, hostLabel(h), itoa(s.Port), string(s.Protocol), string(s.State),
			s.Name,
			triageLabel(s.Triage.Status), oneLine(s.Triage.Note, 2000),
			s.Triage.UpdatedByName, tsPtr(s.Triage.UpdatedAt),
			s.Product, s.Version, s.ExtraInfo, s.Tunnel, s.OSType,
			strings.Join(s.CPEs, " "),
			httpStatus, httpTitle, httpServer,
			tlsSubject, tlsIssuer, tlsExpiry, tlsFP,
			strings.Join(sshKeys, " "),
			oneLine(s.Banner, 300),
			itoa(s.Confidence), s.Method,
			ts(s.FirstSeen), ts(s.LastSeen),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func writeFindingsCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)
	hosts := hostIndex(d)

	if err := cw.Write([]string{
		"severity", "check_id", "title", "network", "ip", "hostname", "port",
		"protocol", "description", "evidence", "remediation", "references",
		"first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, f := range d.Findings {
		port := ""
		if f.Port != 0 {
			port = itoa(f.Port)
		}
		if err := cw.Write([]string{
			string(f.Severity), f.CheckID, f.Title,
			netName(names, f.NetworkID), f.IP, hostLabel(hosts[f.HostID]),
			port, string(f.Protocol),
			oneLine(f.Description, 2000), oneLine(f.Evidence, 2000),
			oneLine(f.Remediation, 2000), strings.Join(f.References, " "),
			ts(f.FirstSeen), ts(f.LastSeen),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func writeReachCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)
	services := serviceIndex(d)

	if err := cw.Write([]string{
		"source_network", "target_network", "ip", "port", "protocol", "service",
		"technique", "vlan_id", "status", "detail", "rtt_ms", "tested_at",
	}); err != nil {
		return err
	}
	for _, r := range d.Reach {
		svcName := ""
		if s, ok := services[r.TargetServiceID]; ok {
			svcName = firstNonEmpty(serviceLabel(s), s.Name)
		}
		port, vlan := "", ""
		if r.Port != 0 {
			port = itoa(r.Port)
		}
		if r.VLANID != 0 {
			vlan = itoa(r.VLANID)
		}
		if err := cw.Write([]string{
			netName(names, r.SourceNetworkID), netName(names, r.TargetNetworkID),
			r.IP, port, string(r.Protocol), svcName,
			r.Technique, vlan, string(r.Status), oneLine(r.Detail, 500),
			strconv.FormatFloat(r.RTTMs, 'f', 2, 64), ts(r.TestedAt),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func writeAssetsCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)

	if err := cw.Write([]string{
		"label", "kind", "hostname", "domain", "os", "networks", "ips",
		"identity_keys", "tags", "notes", "first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, a := range d.Assets {
		var ips, nets []string
		seenNet := map[int64]bool{}
		for _, ip := range a.IPs {
			ips = append(ips, ip.IP)
			if !seenNet[ip.NetworkID] {
				seenNet[ip.NetworkID] = true
				nets = append(nets, netName(names, ip.NetworkID))
			}
		}
		var keys []string
		for _, k := range a.Keys {
			keys = append(keys, fmt.Sprintf("%s=%s(%d)", k.Kind, k.Value, k.Confidence))
		}
		if err := cw.Write([]string{
			a.Label, string(a.Kind), a.Hostname, a.Domain, a.OS,
			strings.Join(nets, " "), strings.Join(ips, " "),
			strings.Join(keys, " "), strings.Join(a.Tags, " "),
			oneLine(a.Notes, 1000), ts(a.FirstSeen), ts(a.LastSeen),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// writeMatrixCSV renders the source × target grid, the table a client reads
// first: which VLAN can reach which.
func writeMatrixCSV(w io.Writer, d model.MissionData) error {
	cw, err := csvWriter(w)
	if err != nil {
		return err
	}
	defer cw.Flush()
	names := networkNames(d)

	ids := make([]int64, 0, len(d.Networks))
	for _, n := range d.Networks {
		ids = append(ids, n.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	cells := make(map[[2]int64]model.MatrixCell, len(d.Matrix))
	for _, c := range d.Matrix {
		cells[[2]int64{c.SourceNetworkID, c.TargetNetworkID}] = c
	}

	header := []string{"source \\ target"}
	for _, id := range ids {
		header = append(header, netName(names, id))
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, src := range ids {
		row := []string{netName(names, src)}
		for _, dst := range ids {
			if src == dst {
				row = append(row, "-")
				continue
			}
			c, ok := cells[[2]int64{src, dst}]
			if !ok {
				row = append(row, "not tested")
				continue
			}
			row = append(row, fmt.Sprintf("%d/%d reachable", c.Reachable, c.Tested))
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

// writeTargets emits a plain ip:port list, ready to pipe into another tool.
func writeTargets(w io.Writer, d model.MissionData) error {
	seen := make(map[string]bool, len(d.Services))
	for _, s := range d.Services {
		line := fmt.Sprintf("%s:%d", s.IP, s.Port)
		if s.Protocol == model.UDP {
			line += "/udp"
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// indexes and small helpers
// ---------------------------------------------------------------------------

func hostIndex(d model.MissionData) map[int64]model.Host {
	out := make(map[int64]model.Host, len(d.Hosts))
	for _, h := range d.Hosts {
		out[h.ID] = h
	}
	return out
}

func serviceIndex(d model.MissionData) map[int64]model.Service {
	out := make(map[int64]model.Service, len(d.Services))
	for _, s := range d.Services {
		out[s.ID] = s
	}
	return out
}

func assetIndex(d model.MissionData) map[int64]string {
	out := make(map[int64]string, len(d.Assets))
	for _, a := range d.Assets {
		out[a.ID] = a.Label
	}
	return out
}

func vlanByNetwork(d model.MissionData) map[int64]int {
	out := make(map[int64]int, len(d.Networks))
	for _, n := range d.Networks {
		out[n.ID] = n.VLANID
	}
	return out
}

func openPortsByHost(d model.MissionData) map[int64]string {
	byHost := map[int64][]string{}
	for _, s := range d.Services {
		byHost[s.HostID] = append(byHost[s.HostID], fmt.Sprintf("%d/%s", s.Port, s.Protocol))
	}
	out := make(map[int64]string, len(byHost))
	for id, list := range byHost {
		out[id] = strings.Join(list, " ")
	}
	return out
}

func servicesByHost(d model.MissionData) map[int64][]model.Service {
	out := map[int64][]model.Service{}
	for _, s := range d.Services {
		out[s.HostID] = append(out[s.HostID], s)
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

// triageLabel renders a status for a human reading a spreadsheet.
func triageLabel(s model.TriageStatus) string {
	switch s {
	case model.TriageInProgress:
		return "in progress"
	case model.TriageDone:
		return "done"
	case model.TriageFlagged:
		return "flagged"
	case model.TriageSkipped:
		return "skipped"
	case "", model.TriageTodo:
		return "to do"
	default:
		return string(s)
	}
}

func tsPtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ts(*t)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// oneLine collapses whitespace and truncates, so a CSV cell stays readable.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max > 0 && len(s) > max {
		return s[:max] + "…"
	}
	return s
}
