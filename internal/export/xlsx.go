package export

import (
	"fmt"
	"io"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/GoToolSharing/nety/internal/model"
)

// The workbook is what gets mailed to the client: one sheet per view, frozen
// header rows, auto-filters and colour-coded severities and matrix cells.
func writeXLSX(w io.Writer, d model.MissionData) error {
	f := excelize.NewFile()
	defer f.Close()

	styles, err := buildStyles(f)
	if err != nil {
		return err
	}
	names := networkNames(d)

	if err := sheetSummary(f, styles, d); err != nil {
		return err
	}
	if err := sheetHosts(f, styles, d, names); err != nil {
		return err
	}
	if err := sheetServices(f, styles, d, names); err != nil {
		return err
	}
	if err := sheetFindings(f, styles, d, names); err != nil {
		return err
	}
	if len(d.Matrix) > 0 || len(d.Reach) > 0 {
		if err := sheetMatrix(f, styles, d, names); err != nil {
			return err
		}
		if err := sheetReach(f, styles, d, names); err != nil {
			return err
		}
	}
	if len(d.Assets) > 0 {
		if err := sheetAssets(f, styles, d, names); err != nil {
			return err
		}
	}

	// Remove the default sheet created by excelize.
	if idx, err := f.GetSheetIndex("Sheet1"); err == nil && idx >= 0 {
		if f.SheetCount > 1 {
			if err := f.DeleteSheet("Sheet1"); err != nil {
				return err
			}
		}
	}
	if idx, err := f.GetSheetIndex("Summary"); err == nil && idx >= 0 {
		f.SetActiveSheet(idx)
	}
	if err := f.Write(w); err != nil {
		return fmt.Errorf("export xlsx: %w", err)
	}
	return nil
}

type xlsxStyles struct {
	header   int
	title    int
	mono     int
	wrap     int
	severity map[model.Severity]int
	triage   map[model.TriageStatus]int
	open     int
	blocked  int
	untested int
}

func buildStyles(f *excelize.File) (xlsxStyles, error) {
	var s xlsxStyles
	var err error

	s.header, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Size: 10},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"1F2937"}},
		Alignment: &excelize.Alignment{Vertical: "center"},
	})
	if err != nil {
		return s, err
	}
	s.title, err = f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 14}})
	if err != nil {
		return s, err
	}
	s.mono, err = f.NewStyle(&excelize.Style{Font: &excelize.Font{Family: "Consolas", Size: 10}})
	if err != nil {
		return s, err
	}
	s.wrap, err = f.NewStyle(&excelize.Style{Alignment: &excelize.Alignment{WrapText: true, Vertical: "top"}})
	if err != nil {
		return s, err
	}

	sevColors := map[model.Severity][2]string{
		model.SevCritical: {"7F1D1D", "FFFFFF"},
		model.SevHigh:     {"C2410C", "FFFFFF"},
		model.SevMedium:   {"FCD34D", "3F2D00"},
		model.SevLow:      {"BFDBFE", "1E3A8A"},
		model.SevInfo:     {"E5E7EB", "374151"},
	}
	s.severity = map[model.Severity]int{}
	for sev, c := range sevColors {
		id, err := f.NewStyle(&excelize.Style{
			Font:      &excelize.Font{Bold: true, Color: c[1], Size: 10},
			Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{c[0]}},
			Alignment: &excelize.Alignment{Horizontal: "center"},
		})
		if err != nil {
			return s, err
		}
		s.severity[sev] = id
	}

	triageColors := map[model.TriageStatus][2]string{
		model.TriageTodo:       {"F3F4F6", "4B5563"},
		model.TriageInProgress: {"DBEAFE", "1D4ED8"},
		model.TriageDone:       {"DCFCE7", "166534"},
		model.TriageFlagged:    {"FEE2E2", "991B1B"},
		model.TriageSkipped:    {"E5E7EB", "6B7280"},
	}
	s.triage = map[model.TriageStatus]int{}
	for status, c := range triageColors {
		id, err := f.NewStyle(&excelize.Style{
			Font:      &excelize.Font{Bold: true, Color: c[1], Size: 10},
			Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{c[0]}},
			Alignment: &excelize.Alignment{Horizontal: "center"},
		})
		if err != nil {
			return s, err
		}
		s.triage[status] = id
	}

	s.open, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "7F1D1D"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"FEE2E2"}},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	if err != nil {
		return s, err
	}
	s.blocked, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "166534"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"DCFCE7"}},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	if err != nil {
		return s, err
	}
	s.untested, err = f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "9CA3AF"},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	return s, err
}

// newSheet creates a sheet with a styled, frozen header row and an autofilter.
func newSheet(f *excelize.File, st xlsxStyles, name string, headers []string, widths []float64) error {
	if _, err := f.NewSheet(name); err != nil {
		return err
	}
	for i, h := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		if err != nil {
			return err
		}
		if err := f.SetCellStr(name, cell, h); err != nil {
			return err
		}
	}
	last, err := excelize.CoordinatesToCellName(len(headers), 1)
	if err != nil {
		return err
	}
	if err := f.SetCellStyle(name, "A1", last, st.header); err != nil {
		return err
	}
	if err := f.SetRowHeight(name, 1, 20); err != nil {
		return err
	}
	if err := f.SetPanes(name, &excelize.Panes{
		Freeze: true, Split: false, XSplit: 0, YSplit: 1,
		TopLeftCell: "A2", ActivePane: "bottomLeft",
	}); err != nil {
		return err
	}
	if err := f.AutoFilter(name, "A1:"+last, nil); err != nil {
		return err
	}
	for i, wdt := range widths {
		col, err := excelize.ColumnNumberToName(i + 1)
		if err != nil {
			return err
		}
		if err := f.SetColWidth(name, col, col, wdt); err != nil {
			return err
		}
	}
	return nil
}

func writeRow(f *excelize.File, sheet string, row int, values []any) error {
	cell, err := excelize.CoordinatesToCellName(1, row)
	if err != nil {
		return err
	}
	return f.SetSheetRow(sheet, cell, &values)
}

func sheetSummary(f *excelize.File, st xlsxStyles, d model.MissionData) error {
	const sheet = "Summary"
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}
	sum := buildSummary(d)

	title := d.Mission.Name
	if d.Mission.Client != "" {
		title = d.Mission.Client + " - " + d.Mission.Name
	}
	if err := f.SetCellStr(sheet, "A1", "Internal network review - "+title); err != nil {
		return err
	}
	if err := f.SetCellStyle(sheet, "A1", "A1", st.title); err != nil {
		return err
	}
	if err := f.SetCellStr(sheet, "A2", "Generated "+d.ExportedAt.Format("2006-01-02 15:04 MST")); err != nil {
		return err
	}
	_ = f.SetColWidth(sheet, "A", "A", 34)
	_ = f.SetColWidth(sheet, "B", "B", 18)

	rows := [][2]any{
		{"Networks reviewed", sum.Networks},
		{"Live hosts", sum.Hosts},
		{"Open services", sum.Services},
		{"Distinct machines", sum.Assets},
		{"Findings", sum.Findings},
		{"Critical", sum.BySeverity[model.SevCritical]},
		{"High", sum.BySeverity[model.SevHigh]},
		{"Medium", sum.BySeverity[model.SevMedium]},
		{"Low", sum.BySeverity[model.SevLow]},
		{"Informational", sum.BySeverity[model.SevInfo]},
		{"Segmentation tests", sum.ReachTested},
		{"Flows that crossed", sum.ReachOK},
	}
	row := 4
	for _, r := range rows {
		if err := writeRow(f, sheet, row, []any{r[0], r[1]}); err != nil {
			return err
		}
		row++
	}
	row++
	if err := writeRow(f, sheet, row, []any{"Most common services", "Hosts"}); err != nil {
		return err
	}
	cell, _ := excelize.CoordinatesToCellName(1, row)
	last, _ := excelize.CoordinatesToCellName(2, row)
	if err := f.SetCellStyle(sheet, cell, last, st.header); err != nil {
		return err
	}
	row++
	for _, pc := range sum.TopPorts {
		label := fmt.Sprintf("%d/%s", pc.Port, pc.Proto)
		if pc.Name != "" {
			label += " " + pc.Name
		}
		if err := writeRow(f, sheet, row, []any{label, pc.Count}); err != nil {
			return err
		}
		row++
	}
	return nil
}

func sheetHosts(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Hosts"
	// The review columns sit where they do on the Services sheet: with the
	// identity of the row. A host the operator skipped is exported like any
	// other, and its status is what tells the reader it was out of scope.
	headers := []string{"Network", "IP", "Hostname",
		"Status", "Note", "Reviewed by", "Reviewed at",
		"Domain", "MAC", "Vendor", "OS", "Machine", "Open ports", "Discovered by", "Last seen"}
	widths := []float64{20, 16, 24, 13, 46, 16, 20, 20, 19, 22, 24, 24, 42, 20, 20}
	if err := newSheet(f, st, sheet, headers, widths); err != nil {
		return err
	}
	assets := assetIndex(d)
	portsByHost := openPortsByHost(d)
	for i, h := range d.Hosts {
		row := i + 2
		if err := writeRow(f, sheet, row, []any{
			netName(names, h.NetworkID), h.IP, h.Hostname,
			triageLabel(h.Triage.Status), h.Triage.Note,
			h.Triage.UpdatedByName, tsPtr(h.Triage.UpdatedAt),
			h.Domain, h.MAC, h.Vendor,
			h.OS, assets[h.AssetID], portsByHost[h.ID],
			strings.Join(h.DiscoveredBy, " "), ts(h.LastSeen),
		}); err != nil {
			return err
		}
		if style, ok := st.triage[h.Triage.Status]; ok {
			cell, _ := excelize.CoordinatesToCellName(4, row)
			if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
				return err
			}
		}
	}
	return nil
}

func sheetServices(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Services"
	headers := []string{"Network", "IP", "Hostname", "Port", "Proto", "State", "Service",
		"Status", "Note", "Reviewed by", "Reviewed at",
		"Product", "Version", "TLS subject", "HTTP title", "Technologies", "Banner", "Confidence"}
	widths := []float64{18, 16, 24, 7, 7, 9, 16, 13, 46, 16, 20, 22, 14, 30, 34, 24, 46, 11}
	if err := newSheet(f, st, sheet, headers, widths); err != nil {
		return err
	}
	hosts := hostIndex(d)
	for i, s := range d.Services {
		tlsSubject, httpTitle, tech := "", "", ""
		if s.TLS != nil {
			tlsSubject = firstNonEmpty(s.TLS.SubjectCN, s.TLS.Subject)
		}
		if s.HTTP != nil {
			httpTitle = s.HTTP.Title
			tech = strings.Join(s.HTTP.Technologies, ", ")
		}
		row := i + 2
		if err := writeRow(f, sheet, row, []any{
			netName(names, s.NetworkID), s.IP, hostLabel(hosts[s.HostID]),
			s.Port, string(s.Protocol), string(s.State), s.Name,
			triageLabel(s.Triage.Status), s.Triage.Note,
			s.Triage.UpdatedByName, tsPtr(s.Triage.UpdatedAt),
			s.Product, s.Version,
			tlsSubject, httpTitle, tech, oneLine(s.Banner, 200), s.Confidence,
		}); err != nil {
			return err
		}
		if style, ok := st.triage[s.Triage.Status]; ok {
			cell, _ := excelize.CoordinatesToCellName(8, row)
			if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
				return err
			}
		}
		noteCell, _ := excelize.CoordinatesToCellName(9, row)
		if err := f.SetCellStyle(sheet, noteCell, noteCell, st.wrap); err != nil {
			return err
		}
	}
	return nil
}

func sheetFindings(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Findings"
	// The review columns sit where they do on the Services sheet: with the
	// identity of the row, ahead of the long text.
	headers := []string{"Severity", "Title", "Network", "IP", "Port", "Check",
		"Status", "Note", "Reviewed by", "Reviewed at",
		"Description", "Evidence", "Remediation"}
	widths := []float64{11, 38, 18, 16, 9, 26, 13, 46, 16, 20, 50, 50, 50}
	if err := newSheet(f, st, sheet, headers, widths); err != nil {
		return err
	}
	for i, fd := range d.Findings {
		row := i + 2
		port := ""
		if fd.Port != 0 {
			port = fmt.Sprintf("%d/%s", fd.Port, fd.Protocol)
		}
		if err := writeRow(f, sheet, row, []any{
			strings.ToUpper(string(fd.Severity)), fd.Title, netName(names, fd.NetworkID),
			fd.IP, port, fd.CheckID,
			triageLabel(fd.Triage.Status), fd.Triage.Note,
			fd.Triage.UpdatedByName, tsPtr(fd.Triage.UpdatedAt),
			fd.Description, fd.Evidence, fd.Remediation,
		}); err != nil {
			return err
		}
		if style, ok := st.severity[fd.Severity]; ok {
			cell, _ := excelize.CoordinatesToCellName(1, row)
			if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
				return err
			}
		}
		if style, ok := st.triage[fd.Triage.Status]; ok {
			cell, _ := excelize.CoordinatesToCellName(7, row)
			if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
				return err
			}
		}
		noteCell, _ := excelize.CoordinatesToCellName(8, row)
		if err := f.SetCellStyle(sheet, noteCell, noteCell, st.wrap); err != nil {
			return err
		}
		from, _ := excelize.CoordinatesToCellName(11, row)
		to, _ := excelize.CoordinatesToCellName(13, row)
		if err := f.SetCellStyle(sheet, from, to, st.wrap); err != nil {
			return err
		}
	}
	return nil
}

func sheetMatrix(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Matrix"
	if _, err := f.NewSheet(sheet); err != nil {
		return err
	}
	ids := networkIDs(d)
	cells := matrixIndex(d)

	if err := f.SetCellStr(sheet, "A1", "source \\ target"); err != nil {
		return err
	}
	for i, id := range ids {
		cell, _ := excelize.CoordinatesToCellName(i+2, 1)
		if err := f.SetCellStr(sheet, cell, netName(names, id)); err != nil {
			return err
		}
	}
	last, _ := excelize.CoordinatesToCellName(len(ids)+1, 1)
	if err := f.SetCellStyle(sheet, "A1", last, st.header); err != nil {
		return err
	}
	_ = f.SetColWidth(sheet, "A", "A", 24)
	if len(ids) > 0 {
		firstCol, _ := excelize.ColumnNumberToName(2)
		lastCol, _ := excelize.ColumnNumberToName(len(ids) + 1)
		_ = f.SetColWidth(sheet, firstCol, lastCol, 20)
	}

	for r, src := range ids {
		row := r + 2
		cell, _ := excelize.CoordinatesToCellName(1, row)
		if err := f.SetCellStr(sheet, cell, netName(names, src)); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheet, cell, cell, st.header); err != nil {
			return err
		}
		for c, dst := range ids {
			cl, _ := excelize.CoordinatesToCellName(c+2, row)
			class, text := htmlCell(src, dst, cells)
			if err := f.SetCellStr(sheet, cl, text); err != nil {
				return err
			}
			style := st.untested
			switch class {
			case "open":
				style = st.open
			case "blocked":
				style = st.blocked
			}
			if err := f.SetCellStyle(sheet, cl, cl, style); err != nil {
				return err
			}
		}
	}
	return f.SetPanes(sheet, &excelize.Panes{
		Freeze: true, XSplit: 1, YSplit: 1, TopLeftCell: "B2", ActivePane: "bottomRight",
	})
}

func sheetReach(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Segmentation"
	headers := []string{"From", "To", "IP", "Port", "Proto", "Service", "Technique", "VLAN", "Status", "Detail", "RTT ms", "Tested at"}
	widths := []float64{20, 20, 16, 7, 7, 22, 18, 7, 14, 40, 9, 20}
	if err := newSheet(f, st, sheet, headers, widths); err != nil {
		return err
	}
	services := serviceIndex(d)
	for i, r := range d.Reach {
		svc := ""
		if s, ok := services[r.TargetServiceID]; ok {
			svc = firstNonEmpty(serviceLabel(s), s.Name)
		}
		row := i + 2
		if err := writeRow(f, sheet, row, []any{
			netName(names, r.SourceNetworkID), netName(names, r.TargetNetworkID),
			r.IP, r.Port, string(r.Protocol), svc, r.Technique, r.VLANID,
			string(r.Status), oneLine(r.Detail, 300), r.RTTMs, ts(r.TestedAt),
		}); err != nil {
			return err
		}
		if r.Status == model.ReachOpen {
			cell, _ := excelize.CoordinatesToCellName(9, row)
			if err := f.SetCellStyle(sheet, cell, cell, st.open); err != nil {
				return err
			}
		}
	}
	return nil
}

func sheetAssets(f *excelize.File, st xlsxStyles, d model.MissionData, names map[int64]string) error {
	const sheet = "Machines"
	headers := []string{"Machine", "Type",
		"Status", "Note", "Reviewed by", "Reviewed at",
		"Hostname", "Domain", "OS", "Networks", "Addresses", "Identified by", "Tags", "First seen", "Last seen"}
	widths := []float64{30, 18, 13, 46, 16, 20, 22, 22, 26, 26, 34, 34, 18, 20, 20}
	if err := newSheet(f, st, sheet, headers, widths); err != nil {
		return err
	}
	for i, a := range d.Assets {
		var ips, nets, keys []string
		seen := map[int64]bool{}
		for _, ip := range a.IPs {
			ips = append(ips, ip.IP)
			if !seen[ip.NetworkID] {
				seen[ip.NetworkID] = true
				nets = append(nets, netName(names, ip.NetworkID))
			}
		}
		for _, k := range a.Keys {
			if k.Confidence >= 70 {
				keys = append(keys, string(k.Kind))
			}
		}
		row := i + 2
		if err := writeRow(f, sheet, row, []any{
			a.Label, string(a.Kind),
			triageLabel(a.Triage.Status), a.Triage.Note,
			a.Triage.UpdatedByName, tsPtr(a.Triage.UpdatedAt),
			a.Hostname, a.Domain, a.OS,
			strings.Join(nets, ", "), strings.Join(ips, ", "),
			strings.Join(dedupe(keys), ", "), strings.Join(a.Tags, ", "),
			ts(a.FirstSeen), ts(a.LastSeen),
		}); err != nil {
			return err
		}
		if style, ok := st.triage[a.Triage.Status]; ok {
			cell, _ := excelize.CoordinatesToCellName(3, row)
			if err := f.SetCellStyle(sheet, cell, cell, style); err != nil {
				return err
			}
		}
	}
	return nil
}

var _ io.Writer = io.Discard
