package api

import (
	"net/http"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// Service triage: the operator's own pass over what a scan found. A scan says
// what is exposed; deciding whether each service is actually a problem is
// manual work, and these endpoints keep track of it so a long engagement does
// not lose its place and a re-scan does not wipe it.

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
	a.ok(w, a.withTriageAuthor(r, sv))
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
	out := a.withTriageAuthor(r, updated)
	a.Bus.PublishData(model.EvtService, sv.MissionID, 0, out)
	a.ok(w, out)
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

// handleTriageSummary powers the progress readout on the services screen.
func (a *API) handleTriageSummary(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	counts, err := a.Store.TriageCounts(r.Context(), m.ID, queryInt64(r, "network_id"))
	if err != nil {
		a.failStore(w, err, "triage counts")
		return
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	reviewed := total - counts[model.TriageTodo]
	a.ok(w, map[string]any{
		"counts": counts, "total": total, "reviewed": reviewed,
		"statuses": model.AllTriageStatuses,
	})
}

// withTriageAuthor fills in who last touched the triage, so the UI can show a
// name instead of a user id.
func (a *API) withTriageAuthor(r *http.Request, sv model.Service) model.Service {
	if sv.Triage.UpdatedBy == 0 {
		return sv
	}
	if u, err := a.Store.UserByID(r.Context(), sv.Triage.UpdatedBy); err == nil {
		sv.Triage.UpdatedByName = firstNonEmptyString(u.DisplayName, u.Username)
	}
	return sv
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
