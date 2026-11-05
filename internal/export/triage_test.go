package export

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// The services CSV is what gets pasted into the client's tracking spreadsheet, so the
// operator's own columns have to be there and in a sensible place.
func TestServicesCSVCarriesTriage(t *testing.T) {
	when := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	data := sampleData()
	data.Services[0].Triage = model.Triage{
		Status:        model.TriageFlagged,
		Note:          "signature SMB non requise; relais testé depuis le VLAN bureaux",
		UpdatedByName: "martina",
		UpdatedAt:     &when,
	}
	data.Services[1].Triage = model.Triage{Status: model.TriageDone, UpdatedByName: "martina"}

	var buf bytes.Buffer
	if err := New().Export(&buf, "csv-services", data, 0); err != nil {
		t.Fatalf("export: %v", err)
	}
	body := bytes.TrimPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF})
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}

	header := rows[0]
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	for _, want := range []string{"triage_status", "triage_note", "triage_by", "triage_at"} {
		if _, ok := idx[want]; !ok {
			t.Fatalf("column %q missing from %v", want, header)
		}
	}
	// They belong with the identity of the service, not buried at the end.
	if idx["triage_status"] > idx["product"] {
		t.Fatalf("the triage columns should come before the fingerprint detail: %v", header)
	}

	var flagged []string
	for _, r := range rows[1:] {
		if r[idx["triage_status"]] == "flagged" {
			flagged = r
		}
		if len(r) != len(header) {
			t.Fatalf("row has %d fields for %d columns", len(r), len(header))
		}
	}
	if flagged == nil {
		t.Fatalf("the flagged service is missing")
	}
	if !strings.Contains(flagged[idx["triage_note"]], "signature SMB") {
		t.Fatalf("note not exported: %q", flagged[idx["triage_note"]])
	}
	if flagged[idx["triage_by"]] != "martina" {
		t.Fatalf("author not exported: %q", flagged[idx["triage_by"]])
	}
	if !strings.HasPrefix(flagged[idx["triage_at"]], "2026-11-04") {
		t.Fatalf("timestamp not exported: %q", flagged[idx["triage_at"]])
	}

	// A service nobody has touched reads as "to do", not as an empty cell.
	untouched := false
	for _, r := range rows[1:] {
		if r[idx["triage_status"]] == "to do" {
			untouched = true
		}
	}
	if !untouched {
		t.Fatal("untriaged services should export as \"to do\"")
	}
}

func TestTriageReachesEveryFormat(t *testing.T) {
	data := sampleData()
	data.Services[0].Triage = model.Triage{
		Status: model.TriageFlagged, Note: "identifiants par defaut acceptes",
	}
	for _, format := range []string{"json", "csv-services", "xlsx", "markdown"} {
		var buf bytes.Buffer
		if err := New().Export(&buf, format, data, 0); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if format == "xlsx" {
			if !bytes.HasPrefix(buf.Bytes(), []byte("PK")) {
				t.Fatalf("xlsx is not a workbook")
			}
			continue
		}
		if !strings.Contains(buf.String(), "flagged") {
			t.Fatalf("%s does not carry the triage status", format)
		}
	}
}

// The findings CSV goes into the same tracking spreadsheet as the services one, so it
// carries the same columns in the same place.
func TestFindingsCSVCarriesTriage(t *testing.T) {
	when := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	data := sampleData()
	data.Findings[0].Triage = model.Triage{
		Status:        model.TriageFlagged,
		Note:          "relais confirmé vers le serveur de fichiers",
		UpdatedByName: "martina",
		UpdatedAt:     &when,
	}

	var buf bytes.Buffer
	if err := New().Export(&buf, "csv-findings", data, 0); err != nil {
		t.Fatalf("export: %v", err)
	}
	body := bytes.TrimPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF})
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}

	header := rows[0]
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	for _, want := range []string{"triage_status", "triage_note", "triage_by", "triage_at"} {
		if _, ok := idx[want]; !ok {
			t.Fatalf("column %q missing from %v", want, header)
		}
	}
	// They belong with the identity of the finding, not buried at the end.
	if idx["triage_status"] > idx["description"] {
		t.Fatalf("the triage columns should come before the description: %v", header)
	}

	var flagged []string
	for _, r := range rows[1:] {
		if len(r) != len(header) {
			t.Fatalf("row has %d fields for %d columns", len(r), len(header))
		}
		if r[idx["triage_status"]] == "flagged" {
			flagged = r
		}
	}
	if flagged == nil {
		t.Fatal("the flagged finding is missing")
	}
	if !strings.Contains(flagged[idx["triage_note"]], "relais confirm") {
		t.Fatalf("note not exported: %q", flagged[idx["triage_note"]])
	}
	if flagged[idx["triage_by"]] != "martina" {
		t.Fatalf("author not exported: %q", flagged[idx["triage_by"]])
	}
	if !strings.HasPrefix(flagged[idx["triage_at"]], "2026-11-04") {
		t.Fatalf("timestamp not exported: %q", flagged[idx["triage_at"]])
	}

	// A finding nobody has touched reads as "to do", not as an empty cell.
	untouched := false
	for _, r := range rows[1:] {
		if r[idx["triage_status"]] == "to do" {
			untouched = true
		}
	}
	if !untouched {
		t.Fatal("untriaged findings should export as \"to do\"")
	}
}

func TestFindingTriageReachesEveryFormat(t *testing.T) {
	data := sampleData()
	data.Findings[0].Triage = model.Triage{
		Status: model.TriageFlagged, Note: "exploite depuis le VLAN bureaux",
	}
	// The services keep their own default so a hit can only come from the finding.
	for i := range data.Services {
		data.Services[i].Triage = model.Triage{Status: model.TriageTodo}
	}
	for _, format := range []string{"json", "csv-findings", "xlsx", "markdown", "html"} {
		var buf bytes.Buffer
		if err := New().Export(&buf, format, data, 0); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if format == "xlsx" {
			if !bytes.HasPrefix(buf.Bytes(), []byte("PK")) {
				t.Fatalf("xlsx is not a workbook")
			}
			continue
		}
		if !strings.Contains(buf.String(), "flagged") {
			t.Fatalf("%s does not carry the finding triage status", format)
		}
		if !strings.Contains(buf.String(), "exploite depuis le VLAN bureaux") {
			t.Fatalf("%s does not carry the finding note", format)
		}
	}
}
