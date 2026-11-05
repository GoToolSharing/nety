// Package export renders a mission in the formats a pentester needs: machine readable
// ones to feed other tools (JSON, CSV, Nmap XML, gnmap, a bare target list) and human
// readable ones for the deliverable (Markdown, HTML, XLSX).
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// Exporter implements engine.Exporter.
type Exporter struct{}

// New builds the exporter.
func New() *Exporter { return &Exporter{} }

var formats = []engine.ExportFormat{
	{ID: "json", Title: "JSON (complete dataset)", Extension: "json", ContentType: "application/json"},
	{ID: "csv-hosts", Title: "CSV - hosts", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-services", Title: "CSV - services", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-findings", Title: "CSV - findings", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-reach", Title: "CSV - segmentation results", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-assets", Title: "CSV - assets", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-matrix", Title: "CSV - segmentation matrix", Extension: "csv", ContentType: "text/csv"},
	{ID: "csv-diff", Title: "CSV - changes since the previous scan", Extension: "csv", ContentType: "text/csv"},
	{ID: "nmap-xml", Title: "Nmap XML", Extension: "xml", ContentType: "text/xml"},
	{ID: "gnmap", Title: "Nmap greppable", Extension: "gnmap", ContentType: "text/plain"},
	{ID: "targets-txt", Title: "Target list (ip:port)", Extension: "txt", ContentType: "text/plain"},
	{ID: "markdown", Title: "Markdown report", Extension: "md", ContentType: "text/markdown"},
	{ID: "html", Title: "HTML report", Extension: "html", ContentType: "text/html"},
	{ID: "xlsx", Title: "Excel workbook", Extension: "xlsx", ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
}

// Formats lists the available formats.
func (e *Exporter) Formats() []engine.ExportFormat {
	out := make([]engine.ExportFormat, len(formats))
	copy(out, formats)
	return out
}

// Format looks a format up by id.
func Format(id string) (engine.ExportFormat, bool) {
	for _, f := range formats {
		if f.ID == id {
			return f, true
		}
	}
	return engine.ExportFormat{}, false
}

// Export writes the mission data in the requested format.
func (e *Exporter) Export(w engine.ExportWriter, format string, data model.MissionData, networkID int64) error {
	out, ok := w.(io.Writer)
	if !ok {
		return fmt.Errorf("export: writer is not an io.Writer")
	}
	if networkID != 0 {
		data = filterByNetwork(data, networkID)
	}
	sortData(&data)

	switch format {
	case "json":
		return writeJSON(out, data)
	case "csv-hosts":
		return writeHostsCSV(out, data)
	case "csv-services":
		return writeServicesCSV(out, data)
	case "csv-findings":
		return writeFindingsCSV(out, data)
	case "csv-reach":
		return writeReachCSV(out, data)
	case "csv-assets":
		return writeAssetsCSV(out, data)
	case "csv-matrix":
		return writeMatrixCSV(out, data)
	case "csv-diff":
		return writeDiffCSV(out, data)
	case "nmap-xml":
		return writeNmapXML(out, data)
	case "gnmap":
		return writeGnmap(out, data)
	case "targets-txt":
		return writeTargets(out, data)
	case "markdown":
		return writeMarkdown(out, data)
	case "html":
		return writeHTML(out, data)
	case "xlsx":
		return writeXLSX(out, data)
	default:
		return fmt.Errorf("export: unknown format %q", format)
	}
}

// Filename suggests a download name.
func Filename(data model.MissionData, format string, networkID int64) string {
	f, ok := Format(format)
	if !ok {
		f.Extension = "dat"
	}
	name := slug(data.Mission.Name)
	if name == "" {
		name = "mission"
	}
	suffix := ""
	if networkID != 0 {
		for _, n := range data.Networks {
			if n.ID == networkID {
				suffix = "-" + slug(n.Name)
				break
			}
		}
	}
	stamp := time.Now().UTC().Format("20060102-1504")
	return fmt.Sprintf("nety-%s%s-%s-%s.%s", name, suffix, format, stamp, f.Extension)
}

func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// --------------------------------------------------------------------------- shared
// helpers ---------------------------------------------------------------------------

func filterByNetwork(d model.MissionData, networkID int64) model.MissionData {
	out := d
	out.Networks = filter(d.Networks, func(n model.Network) bool { return n.ID == networkID })
	out.Hosts = filter(d.Hosts, func(h model.Host) bool { return h.NetworkID == networkID })
	out.Services = filter(d.Services, func(s model.Service) bool { return s.NetworkID == networkID })
	out.Findings = filter(d.Findings, func(f model.Finding) bool { return f.NetworkID == networkID })
	out.Reach = filter(d.Reach, func(r model.ReachResult) bool {
		return r.SourceNetworkID == networkID || r.TargetNetworkID == networkID
	})
	out.Matrix = filter(d.Matrix, func(c model.MatrixCell) bool {
		return c.SourceNetworkID == networkID || c.TargetNetworkID == networkID
	})
	out.Scans = filter(d.Scans, func(s model.Scan) bool { return s.NetworkID == networkID })
	// The diff is about one network already. Keep it only when it is the one being
	// exported, so a per-network file never carries another VLAN's changes.
	if out.Diff != nil && out.Diff.NetworkID != networkID {
		out.Diff = nil
	}
	return out
}

func filter[T any](in []T, keep func(T) bool) []T {
	out := make([]T, 0, len(in))
	for _, v := range in {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

// sortData gives every export a stable, human-friendly order.
func sortData(d *model.MissionData) {
	sort.SliceStable(d.Hosts, func(i, j int) bool {
		if d.Hosts[i].NetworkID != d.Hosts[j].NetworkID {
			return d.Hosts[i].NetworkID < d.Hosts[j].NetworkID
		}
		return ipLess(d.Hosts[i].IP, d.Hosts[j].IP)
	})
	sort.SliceStable(d.Services, func(i, j int) bool {
		a, b := d.Services[i], d.Services[j]
		if a.NetworkID != b.NetworkID {
			return a.NetworkID < b.NetworkID
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	sort.SliceStable(d.Findings, func(i, j int) bool {
		a, b := d.Findings[i], d.Findings[j]
		if sevWeight(a.Severity) != sevWeight(b.Severity) {
			return sevWeight(a.Severity) < sevWeight(b.Severity)
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		return a.Port < b.Port
	})
	sort.SliceStable(d.Reach, func(i, j int) bool {
		a, b := d.Reach[i], d.Reach[j]
		if a.SourceNetworkID != b.SourceNetworkID {
			return a.SourceNetworkID < b.SourceNetworkID
		}
		if a.TargetNetworkID != b.TargetNetworkID {
			return a.TargetNetworkID < b.TargetNetworkID
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Technique < b.Technique
	})
	sort.SliceStable(d.Assets, func(i, j int) bool { return d.Assets[i].Label < d.Assets[j].Label })
	sort.SliceStable(d.Networks, func(i, j int) bool { return d.Networks[i].ID < d.Networks[j].ID })
	sort.SliceStable(d.Matrix, func(i, j int) bool {
		if d.Matrix[i].SourceNetworkID != d.Matrix[j].SourceNetworkID {
			return d.Matrix[i].SourceNetworkID < d.Matrix[j].SourceNetworkID
		}
		return d.Matrix[i].TargetNetworkID < d.Matrix[j].TargetNetworkID
	})
}

func sevWeight(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 0
	case model.SevHigh:
		return 1
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 3
	default:
		return 4
	}
}

// ipLess orders IPv4 numerically and keeps IPv6 lexicographic, which is good enough for a
// report and never panics on a malformed value.
func ipLess(a, b string) bool {
	pa, oka := ipKey(a)
	pb, okb := ipKey(b)
	if oka && okb {
		return pa < pb
	}
	return a < b
}

func ipKey(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, false
		}
		v = v<<8 | uint32(n)
	}
	return v, true
}

// networkNames maps network ids to display names.
func networkNames(d model.MissionData) map[int64]string {
	out := make(map[int64]string, len(d.Networks))
	for _, n := range d.Networks {
		label := n.Name
		if n.VLANID != 0 {
			label = fmt.Sprintf("%s (VLAN %d)", n.Name, n.VLANID)
		}
		out[n.ID] = label
	}
	return out
}

func netName(names map[int64]string, id int64) string {
	if n, ok := names[id]; ok {
		return n
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("network-%d", id)
}

// serviceLabel renders "product version (extra)" compactly.
func serviceLabel(s model.Service) string {
	parts := make([]string, 0, 3)
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	label := strings.Join(parts, " ")
	if s.ExtraInfo != "" {
		if label != "" {
			label += " "
		}
		label += "(" + s.ExtraInfo + ")"
	}
	return label
}

func hostLabel(h model.Host) string {
	if h.Hostname != "" {
		if h.Domain != "" && !strings.Contains(h.Hostname, ".") {
			return h.Hostname + "." + h.Domain
		}
		return h.Hostname
	}
	return h.IP
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeJSON(w io.Writer, d model.MissionData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("export json: %w", err)
	}
	return nil
}

// csvWriter wraps encoding/csv with a UTF-8 BOM so Excel opens accented client names
// correctly.
func csvWriter(w io.Writer) (*csv.Writer, error) {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return nil, err
	}
	return csv.NewWriter(w), nil
}

// scopeLine is the sentence every export carries about how much of the mission it holds.
// An export that leaves rows out must say so itself: the file outlives the screen it was
// produced from, and nobody reading it later knows which boxes were ticked.
func scopeLine(d model.MissionData) string {
	if !d.Omitted.Any() {
		if d.Omitted == nil {
			return "Scope: the whole mission, including every row whatever its status."
		}
		return "Scope: the whole mission. Nothing was held back."
	}
	var reasons []string
	if r := countList(d.Omitted.SetAside); r != "" {
		reasons = append(reasons, r+" set aside (skipped or called a false positive)")
	}
	if r := countList(d.Omitted.Unreviewed); r != "" {
		reasons = append(reasons, r+" nobody had reviewed yet")
	}
	return "Scope: left out of this export: " + strings.Join(reasons, "; and ") + "."
}

// countList renders one reason's counts as "27 findings, 2 hosts".
func countList(c model.OmittedCounts) string {
	var parts []string
	add := func(n int, singular, plural string) {
		if n == 0 {
			return
		}
		word := plural
		if n == 1 {
			word = singular
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, word))
	}
	add(c.Findings, "finding", "findings")
	add(c.Services, "service", "services")
	add(c.Hosts, "host", "hosts")
	add(c.Assets, "machine", "machines")
	add(c.Reach, "segmentation result", "segmentation results")
	return strings.Join(parts, ", ")
}
