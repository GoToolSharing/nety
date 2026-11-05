package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/GoToolSharing/nety/internal/export"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

func (a *API) handleListHosts(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	address, ok := a.addressQuery(w, r)
	if !ok {
		return
	}
	hosts, err := a.Store.ListHostsFiltered(r.Context(), store.HostFilter{
		MissionID: m.ID,
		NetworkID: queryInt64(r, "network_id"),
		Address:   address,
		Sort:      r.URL.Query().Get("sort"),
		Desc:      sortDescending(r),
	})
	if err != nil {
		a.failStore(w, err, "hosts")
		return
	}
	a.ok(w, hosts)
}

// addressQuery reads the `ip` parameter shared by the result listings. It
// takes a single address or a CIDR prefix, v4 or v6, and answers false once it
// has already written the error response.
//
// A malformed value is refused here rather than quietly matching nothing: an
// operator who mistypes a subnet should be told, not shown an empty table.
func (a *API) addressQuery(w http.ResponseWriter, r *http.Request) (store.AddressFilter, bool) {
	f, err := store.ParseAddressFilter(r.URL.Query().Get("ip"))
	if err != nil {
		a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		return store.AddressFilter{}, false
	}
	return f, true
}

// sortDescending reads the `dir` parameter shared by the result listings.
// Anything but an explicit "desc" means ascending, which is what the first
// click on a column header asks for.
func sortDescending(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("dir")), "desc")
}

func (a *API) handleGetHost(w http.ResponseWriter, r *http.Request, u model.User) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}
	host, err := a.Store.Host(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "host")
		return
	}
	if _, ok := a.missionByID(w, r, u, host.MissionID); !ok {
		return
	}
	services, err := a.Store.ServicesForHost(r.Context(), host.ID)
	if err != nil {
		a.failStore(w, err, "services")
		return
	}
	var asset *model.Asset
	if host.AssetID != 0 {
		if v, err := a.Store.Asset(r.Context(), host.AssetID); err == nil {
			asset = &v
		}
	}
	// The caller asked for this host by id, so its own screen shows everything
	// it has even when it is skipped and hidden from the mission listings.
	findings, err := a.Store.ListFindings(r.Context(), store.FindingFilter{
		MissionID: host.MissionID, NetworkID: host.NetworkID, HostID: host.ID,
		IncludeSkippedHosts: true,
	})
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	a.ok(w, map[string]any{
		"host": host, "services": services, "asset": asset,
		"findings": fillTriageAuthors(a, r, findings, func(f *model.Finding) *model.Triage { return &f.Triage }),
	})
}

func (a *API) handleListServices(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	address, ok := a.addressQuery(w, r)
	if !ok {
		return
	}
	filter := store.ServiceFilter{
		MissionID:           m.ID,
		NetworkID:           queryInt64(r, "network_id"),
		HostID:              queryInt64(r, "host_id"),
		Port:                queryInt(r, "port", 0),
		Protocol:            model.Protocol(strings.ToLower(q.Get("protocol"))),
		Search:              q.Get("q"),
		Address:             address,
		Sort:                q.Get("sort"),
		Desc:                sortDescending(r),
		IncludeSkippedHosts: includeSkipped(r),
		Limit:               queryInt(r, "limit", 0),
		Offset:              queryInt(r, "offset", 0),
	}
	statuses, ok := a.triageQuery(w, r)
	if !ok {
		return
	}
	filter.Triage = statuses
	if filter.Protocol != "" && filter.Protocol != model.TCP && filter.Protocol != model.UDP {
		a.fail(w, http.StatusBadRequest, "invalid", "protocol must be tcp or udp")
		return
	}
	if filter.Limit > 5000 {
		filter.Limit = 5000
	}
	services, err := a.Store.ListServices(r.Context(), filter)
	if err != nil {
		a.failStore(w, err, "services")
		return
	}
	a.ok(w, fillTriageAuthors(a, r, services, func(sv *model.Service) *model.Triage { return &sv.Triage }))
}

// triageQuery reads the repeatable, comma separated `triage` parameter shared
// by the service and finding listings. It answers false once it has already
// written the error response.
func (a *API) triageQuery(w http.ResponseWriter, r *http.Request) ([]model.TriageStatus, bool) {
	var out []model.TriageStatus
	for _, v := range r.URL.Query()["triage"] {
		for _, part := range strings.Split(v, ",") {
			st := model.TriageStatus(strings.TrimSpace(part))
			if st == "" {
				continue
			}
			if !model.ValidTriageStatus(st) {
				a.fail(w, http.StatusBadRequest, "invalid", "unknown triage status "+string(st))
				return nil, false
			}
			out = append(out, st)
		}
	}
	return out, true
}

// fillTriageAuthors resolves the triage author names in one pass rather than
// one query per row. pick points at the triage record carried by each item,
// which is the only thing services and findings have in common here.
func fillTriageAuthors[T any](a *API, r *http.Request, items []T, pick func(*T) *model.Triage) []T {
	need := false
	for i := range items {
		if pick(&items[i]).UpdatedBy != 0 {
			need = true
			break
		}
	}
	if !need {
		return items
	}
	users, err := a.Store.ListUsers(r.Context())
	if err != nil {
		return items
	}
	byID := make(map[int64]string, len(users))
	for _, u := range users {
		byID[u.ID] = firstNonEmptyString(u.DisplayName, u.Username)
	}
	for i := range items {
		t := pick(&items[i])
		if name, ok := byID[t.UpdatedBy]; ok {
			t.UpdatedByName = name
		}
	}
	return items
}

func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	statuses, ok := a.triageQuery(w, r)
	if !ok {
		return
	}
	address, ok := a.addressQuery(w, r)
	if !ok {
		return
	}
	findings, err := a.Store.ListFindings(r.Context(), store.FindingFilter{
		MissionID:           m.ID,
		NetworkID:           queryInt64(r, "network_id"),
		HostID:              queryInt64(r, "host_id"),
		Address:             address,
		Sort:                r.URL.Query().Get("sort"),
		Desc:                sortDescending(r),
		Triage:              statuses,
		IncludeSkippedHosts: includeSkipped(r),
	})
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	a.ok(w, fillTriageAuthors(a, r, findings, func(f *model.Finding) *model.Triage { return &f.Triage }))
}

func (a *API) handleListAssets(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	address, ok := a.addressQuery(w, r)
	if !ok {
		return
	}
	assets, err := a.Store.ListAssetsFiltered(r.Context(), store.AssetFilter{
		MissionID: m.ID,
		Address:   address,
		Sort:      r.URL.Query().Get("sort"),
		Desc:      sortDescending(r),
	})
	if err != nil {
		a.failStore(w, err, "assets")
		return
	}
	a.ok(w, assets)
}

func (a *API) requireAsset(w http.ResponseWriter, r *http.Request, u model.User) (model.Asset, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Asset{}, false
	}
	asset, err := a.Store.Asset(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "asset")
		return model.Asset{}, false
	}
	if _, ok := a.missionByID(w, r, u, asset.MissionID); !ok {
		return model.Asset{}, false
	}
	return asset, true
}

func (a *API) handleGetAsset(w http.ResponseWriter, r *http.Request, u model.User) {
	asset, ok := a.requireAsset(w, r, u)
	if !ok {
		return
	}
	hosts, err := a.Store.ListHosts(r.Context(), asset.MissionID, 0)
	if err != nil {
		a.failStore(w, err, "hosts")
		return
	}
	mine := hosts[:0]
	for _, h := range hosts {
		if h.AssetID == asset.ID {
			mine = append(mine, h)
		}
	}
	a.ok(w, map[string]any{"asset": asset, "hosts": mine})
}

// handleUpdateAsset edits a machine. Besides the label and the rest, it is
// also where the machine is triaged, under the same `status` and `note` fields
// a service or a finding takes: an asset is one thing, and one PATCH changes
// it. A status set here reaches every address of the machine (see
// store.SetAssetTriage).
func (a *API) handleUpdateAsset(w http.ResponseWriter, r *http.Request, u model.User) {
	asset, ok := a.requireAsset(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Label  *string             `json:"label"`
		Notes  *string             `json:"notes"`
		Tags   *[]string           `json:"tags"`
		Kind   *model.AssetKind    `json:"kind"`
		Status *model.TriageStatus `json:"status"`
		Note   *string             `json:"note"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Status != nil && !model.ValidTriageStatus(*req.Status) {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown status")
		return
	}
	if req.Status != nil || req.Note != nil {
		updated, hosts, err := a.Store.SetAssetTriage(r.Context(), asset.ID, req.Status, req.Note, u.ID)
		if err != nil {
			a.failStore(w, err, "asset")
			return
		}
		detail := updated.Label + " -> " + string(updated.Triage.Status)
		if req.Status != nil {
			detail += " (" + itoa64(hosts) + " addresses)"
		}
		a.audit(r, u, asset.MissionID, "asset.triaged", detail)
		a.withTriageAuthor(r, &updated.Triage)
		a.Bus.PublishData(model.EvtAsset, asset.MissionID, 0, updated)
		// A machine going out of scope takes its addresses with it, and every
		// table keyed on those addresses changes under the operator's feet.
		if req.Status != nil {
			a.Bus.PublishData(model.EvtScanLog, asset.MissionID, 0, model.LogLine{
				Level: "info", Message: "triage updated, resynchronise",
			})
		}
		asset = updated
	}
	if req.Label == nil && req.Notes == nil && req.Tags == nil && req.Kind == nil {
		if req.Status == nil && req.Note == nil {
			a.fail(w, http.StatusBadRequest, "invalid", "nothing to change")
			return
		}
		a.ok(w, asset)
		return
	}
	if req.Label != nil {
		asset.Label = strings.TrimSpace(*req.Label)
	}
	if req.Notes != nil {
		asset.Notes = *req.Notes
	}
	if req.Tags != nil {
		asset.Tags = *req.Tags
	}
	if req.Kind != nil {
		asset.Kind = *req.Kind
	}
	saved, err := a.Store.SaveAsset(r.Context(), asset)
	if err != nil {
		a.failStore(w, err, "asset")
		return
	}
	a.audit(r, u, asset.MissionID, "asset.updated", saved.Label)
	a.Bus.PublishData(model.EvtAsset, asset.MissionID, 0, saved)
	a.ok(w, saved)
}

func (a *API) handleMergeAssets(w http.ResponseWriter, r *http.Request, u model.User) {
	asset, ok := a.requireAsset(w, r, u)
	if !ok {
		return
	}
	var req struct {
		SourceID int64 `json:"source_id"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	source, err := a.Store.Asset(r.Context(), req.SourceID)
	if err != nil {
		a.failStore(w, err, "asset")
		return
	}
	if source.MissionID != asset.MissionID {
		a.fail(w, http.StatusBadRequest, "invalid", "both machines must belong to the same mission")
		return
	}
	if source.ID == asset.ID {
		a.fail(w, http.StatusBadRequest, "invalid", "cannot merge a machine into itself")
		return
	}
	if err := a.Store.MergeAssets(r.Context(), asset.ID, source.ID); err != nil {
		a.failStore(w, err, "asset")
		return
	}
	merged, err := a.Store.Asset(r.Context(), asset.ID)
	if err != nil {
		a.failStore(w, err, "asset")
		return
	}
	a.audit(r, u, asset.MissionID, "asset.merged", source.Label+" → "+merged.Label)
	a.Bus.PublishData(model.EvtAsset, asset.MissionID, 0, merged)
	a.ok(w, merged)
}

func (a *API) handleListReach(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	results, err := a.Store.ListReach(r.Context(), store.ReachFilter{
		MissionID:           m.ID,
		SourceNetworkID:     queryInt64(r, "source_network_id"),
		IncludeSkippedHosts: includeSkipped(r),
	})
	if err != nil {
		a.failStore(w, err, "reachability results")
		return
	}
	a.ok(w, results)
}

// handleMatrix returns everything the matrix screen needs in one call.
func (a *API) handleMatrix(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	networks, err := a.Store.ListNetworks(r.Context(), m.ID)
	if err != nil {
		a.failStore(w, err, "networks")
		return
	}
	cells, err := a.Store.Matrix(r.Context(), m.ID, includeSkipped(r))
	if err != nil {
		a.failStore(w, err, "matrix")
		return
	}
	resp := map[string]any{"networks": networks, "cells": cells}
	if a.Engines.Segment != nil {
		resp["techniques"] = a.Engines.Segment.Techniques()
	}
	a.ok(w, resp)
}

// handleScanDiff answers what changed between two scans of the same network.
//
// The scan in the path is one end of the comparison and `against` the other.
// Which of the two is the baseline is decided by when they ran, not by how
// they were passed, so the answer always names both ends explicitly.
func (a *API) handleScanDiff(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	scanID, ok := a.pathScanID(w, r)
	if !ok {
		return
	}
	sc, err := a.Store.Scan(r.Context(), scanID)
	if err != nil {
		a.failStore(w, err, "scan")
		return
	}
	if sc.MissionID != m.ID {
		// Do not confirm a scan of another mission exists.
		a.fail(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}

	against := queryInt64(r, "against")
	picked := against == 0
	var other model.Scan
	switch {
	case picked:
		other, err = a.Store.PreviousScan(r.Context(), sc)
		if errors.Is(err, store.ErrNotFound) {
			// Not an error: this is simply the first pass over the network.
			a.ok(w, model.ScanDiff{
				MissionID: m.ID, NetworkID: sc.NetworkID,
				To: model.ScanRefOf(sc), FromPicked: true,
				Message: "no earlier completed scan of this network to compare with",
			})
			return
		}
		if err != nil {
			a.failStore(w, err, "scan")
			return
		}
	case against == sc.ID:
		a.fail(w, http.StatusBadRequest, "invalid", "a scan cannot be compared with itself")
		return
	default:
		other, err = a.Store.Scan(r.Context(), against)
		if err != nil {
			a.failStore(w, err, "scan")
			return
		}
		if other.MissionID != m.ID {
			a.fail(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		if other.NetworkID != sc.NetworkID {
			a.fail(w, http.StatusBadRequest, "invalid",
				"the two scans are on different networks, so there is nothing in common to compare")
			return
		}
	}

	diff, err := a.Store.ScanDiff(r.Context(), other, sc)
	if err != nil {
		a.failStore(w, err, "scan diff")
		return
	}
	diff.FromPicked = picked
	a.ok(w, diff)
}

// exportDiff works out which pair of scans the diff in an export is about.
//
// `scan_id` and `against` name them. With neither, it is the last completed
// scan of the mission against the one before it on the same network, which is
// what an operator means by "what changed". A mission scanned only once has no
// diff, and the sheet comes out with its header alone.
func (a *API) exportDiff(r *http.Request, missionID, networkID int64) *model.ScanDiff {
	ctx := r.Context()
	var (
		to  model.Scan
		err error
	)
	if id := queryInt64(r, "scan_id"); id != 0 {
		if to, err = a.Store.Scan(ctx, id); err != nil || to.MissionID != missionID {
			return nil
		}
	} else if to, err = a.Store.LatestCompletedScan(ctx, missionID, networkID); err != nil {
		return nil
	}

	var from model.Scan
	picked := queryInt64(r, "against") == 0
	if picked {
		if from, err = a.Store.PreviousScan(ctx, to); err != nil {
			return nil
		}
	} else if from, err = a.Store.Scan(ctx, queryInt64(r, "against")); err != nil ||
		from.MissionID != missionID || from.NetworkID != to.NetworkID {
		return nil
	}

	diff, err := a.Store.ScanDiff(ctx, from, to)
	if err != nil {
		// An export that cannot work out the diff is still worth sending.
		a.Log.Warn("cannot build the export diff", "mission", missionID, "error", err)
		return nil
	}
	diff.FromPicked = picked
	return &diff
}

// handleExport streams a mission in the requested format.
func (a *API) handleExport(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	meta, known := export.Format(format)
	if !known {
		a.fail(w, http.StatusBadRequest, "invalid", "unknown export format "+format)
		return
	}
	networkID := queryInt64(r, "network_id")

	// An export is a deliverable, so what the operator set aside stays out of
	// it by default: a skipped host or machine with everything attached to
	// it, and the services and findings marked skipped or a false positive.
	// `include_dismissed=1` asks for the whole record instead, which is what
	// a handover to another tester needs. Either way the file says which of
	// the two it is, and how many rows were held back.
	scope := store.ExportScope{
		NetworkID:        networkID,
		IncludeDismissed: queryYes(r, "include_dismissed"),
	}
	data, err := a.Store.MissionData(r.Context(), m.ID, scope)
	if err != nil {
		a.failStore(w, err, "mission data")
		return
	}
	data.ExportedBy = u.Username
	data.Diff = a.exportDiff(r, m.ID, networkID)

	filename := export.Filename(data, format, networkID)
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		"attachment; filename=\""+filename+"\"; filename*=UTF-8''"+url.PathEscape(filename))

	if err := a.Exporter.Export(w, format, data, networkID); err != nil {
		// Headers are already sent; log and cut the response short rather than
		// pretending the file is complete.
		a.Log.Error("export failed", "mission", m.ID, "format", format, "error", err)
		return
	}
	detail := format
	if data.Omitted.Any() {
		detail += fmt.Sprintf(" (%d rows set aside left out)", data.Omitted.Total())
	}
	a.audit(r, u, m.ID, "mission.exported", detail)
}
