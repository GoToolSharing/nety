package api

import (
	"net/http"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// Triage: the operator's own pass over what a scan found. A scan says what is
// exposed and which checks fired; deciding whether each service, and each
// finding, is actually a problem is manual work, and these endpoints keep
// track of it so a long engagement does not lose its place and a re-scan does
// not wipe it. Services and findings are handled the same way on purpose:
// going from one screen to the other should not mean learning anything new.

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

// requireService loads a service and checks the caller may see its mission.
func (a *API) requireService(w http.ResponseWriter, r *http.Request, u model.User) (model.Service, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Service{}, false
	}
	sv, err := a.Store.Service(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "service")
		return model.Service{}, false
	}
	if _, ok := a.missionByID(w, r, u, sv.MissionID); !ok {
		return model.Service{}, false
	}
	return sv, true
}

func (a *API) handleGetService(w http.ResponseWriter, r *http.Request, u model.User) {
	sv, ok := a.requireService(w, r, u)
	if !ok {
		return
	}
	a.withTriageAuthor(r, &sv.Triage)
	a.ok(w, sv)
}

// handleTriageService records a status, a note, or both. A field left out is
// left alone, so the note survives a status change and the other way round.
func (a *API) handleTriageService(w http.ResponseWriter, r *http.Request, u model.User) {
	sv, ok := a.requireService(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Status *model.TriageStatus `json:"status"`
		Note   *string             `json:"note"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Status == nil && req.Note == nil {
		a.fail(w, http.StatusBadRequest, "invalid", "give a status, a note, or both")
		return
	}
	if req.Status != nil && !model.ValidTriageStatus(*req.Status) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown status")
		return
	}
	updated, err := a.Store.SetServiceTriage(r.Context(), sv.ID, req.Status, req.Note, u.ID)
	if err != nil {
		a.failStore(w, err, "service")
		return
	}
	a.audit(r, u, sv.MissionID, "service.triaged",
		endpointOf(sv)+" -> "+string(updated.Triage.Status))
	a.withTriageAuthor(r, &updated.Triage)
	a.Bus.PublishData(model.EvtService, sv.MissionID, 0, updated)
	a.ok(w, updated)
}

// handleBulkTriage applies one status to a selection, which is how a batch of
// uninteresting ports gets cleared in a single gesture.
func (a *API) handleBulkTriage(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var req struct {
		ServiceIDs []int64            `json:"service_ids"`
		Status     model.TriageStatus `json:"status"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if !model.ValidTriageStatus(req.Status) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown status")
		return
	}
	if len(req.ServiceIDs) == 0 {
		a.fail(w, http.StatusBadRequest, "invalid", "no service selected")
		return
	}
	if len(req.ServiceIDs) > 5000 {
		a.fail(w, http.StatusBadRequest, "invalid", "too many services in one call")
		return
	}
	n, err := a.Store.BulkSetServiceTriage(r.Context(), m.ID, req.ServiceIDs, req.Status, u.ID)
	if err != nil {
		a.failStore(w, err, "services")
		return
	}
	a.audit(r, u, m.ID, "service.triaged_bulk",
		itoa64(n)+" services -> "+string(req.Status))
	// Tell every open browser to refresh the table rather than publishing
	// thousands of individual rows.
	a.Bus.PublishData(model.EvtScanLog, m.ID, 0, model.LogLine{
		Level: "info", Message: "triage updated, resynchronise",
	})
	a.ok(w, map[string]any{"updated": n, "status": req.Status})
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// requireFinding loads a finding and checks the caller may see its mission.
func (a *API) requireFinding(w http.ResponseWriter, r *http.Request, u model.User) (model.Finding, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Finding{}, false
	}
	f, err := a.Store.Finding(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "finding")
		return model.Finding{}, false
	}
	if _, ok := a.missionByID(w, r, u, f.MissionID); !ok {
		return model.Finding{}, false
	}
	return f, true
}

func (a *API) handleGetFinding(w http.ResponseWriter, r *http.Request, u model.User) {
	f, ok := a.requireFinding(w, r, u)
	if !ok {
		return
	}
	a.withTriageAuthor(r, &f.Triage)
	a.ok(w, f)
}

// handleTriageFinding records a status, a note, or both, exactly as the
// service version does: a field left out is left alone.
func (a *API) handleTriageFinding(w http.ResponseWriter, r *http.Request, u model.User) {
	f, ok := a.requireFinding(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Status *model.TriageStatus `json:"status"`
		Note   *string             `json:"note"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Status == nil && req.Note == nil {
		a.fail(w, http.StatusBadRequest, "invalid", "give a status, a note, or both")
		return
	}
	if req.Status != nil && !model.ValidTriageStatus(*req.Status) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown status")
		return
	}
	updated, err := a.Store.SetFindingTriage(r.Context(), f.ID, req.Status, req.Note, u.ID)
	if err != nil {
		a.failStore(w, err, "finding")
		return
	}
	a.audit(r, u, f.MissionID, "finding.triaged",
		f.CheckID+" on "+f.IP+" -> "+string(updated.Triage.Status))
	a.withTriageAuthor(r, &updated.Triage)
	a.Bus.PublishData(model.EvtFinding, f.MissionID, 0, updated)
	a.ok(w, updated)
}

// handleBulkFindingTriage applies one status to a selection, which is how a
// wave of informational checks gets cleared in a single gesture.
func (a *API) handleBulkFindingTriage(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var req struct {
		FindingIDs []int64            `json:"finding_ids"`
		Status     model.TriageStatus `json:"status"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if !model.ValidTriageStatus(req.Status) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown status")
		return
	}
	if len(req.FindingIDs) == 0 {
		a.fail(w, http.StatusBadRequest, "invalid", "no finding selected")
		return
	}
	if len(req.FindingIDs) > 5000 {
		a.fail(w, http.StatusBadRequest, "invalid", "too many findings in one call")
		return
	}
	n, err := a.Store.BulkSetFindingTriage(r.Context(), m.ID, req.FindingIDs, req.Status, u.ID)
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	a.audit(r, u, m.ID, "finding.triaged_bulk",
		itoa64(n)+" findings -> "+string(req.Status))
	// Tell every open browser to refresh the table rather than publishing
	// thousands of individual rows.
	a.Bus.PublishData(model.EvtScanLog, m.ID, 0, model.LogLine{
		Level: "info", Message: "triage updated, resynchronise",
	})
	a.ok(w, map[string]any{"updated": n, "status": req.Status})
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// handleTriageSummary powers the progress readout on the services and the
// findings screens.
//
// The service counts stay at the top level, where they have always been, and
// the findings arrive beside them under their own key rather than mixed into
// the same totals: the two passes are counted separately because they are
// done separately.
func (a *API) handleTriageSummary(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	networkID := queryInt64(r, "network_id")
	services, err := a.Store.TriageCounts(r.Context(), m.ID, networkID)
	if err != nil {
		a.failStore(w, err, "triage counts")
		return
	}
	findings, err := a.Store.FindingTriageCounts(r.Context(), m.ID, networkID)
	if err != nil {
		a.failStore(w, err, "triage counts")
		return
	}
	total, reviewed := triageTotals(services)
	findingTotal, findingReviewed := triageTotals(findings)
	a.ok(w, map[string]any{
		"counts": services, "total": total, "reviewed": reviewed,
		"statuses": model.AllTriageStatuses,
		"findings": map[string]any{
			"counts": findings, "total": findingTotal, "reviewed": findingReviewed,
		},
	})
}

// triageTotals counts everything, then everything that is no longer to do.
func triageTotals(counts map[model.TriageStatus]int) (total, reviewed int) {
	for _, n := range counts {
		total += n
	}
	return total, total - counts[model.TriageTodo]
}

// withTriageAuthor fills in who last touched the triage, so the UI can show a
// name instead of a user id.
func (a *API) withTriageAuthor(r *http.Request, t *model.Triage) {
	if t.UpdatedBy == 0 {
		return
	}
	if u, err := a.Store.UserByID(r.Context(), t.UpdatedBy); err == nil {
		t.UpdatedByName = firstNonEmptyString(u.DisplayName, u.Username)
	}
}

func firstNonEmptyString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func endpointOf(sv model.Service) string {
	return sv.IP + ":" + itoa64(int64(sv.Port)) + "/" + string(sv.Protocol)
}

var _ = store.ErrNotFound
