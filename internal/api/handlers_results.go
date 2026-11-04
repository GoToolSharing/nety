package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/vaadata/nety/internal/export"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/store"
)

func (a *API) handleListHosts(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	hosts, err := a.Store.ListHosts(r.Context(), m.ID, queryInt64(r, "network_id"))
	if err != nil {
		a.failStore(w, err, "hosts")
		return
	}
	a.ok(w, hosts)
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
	findings, err := a.Store.ListFindings(r.Context(), host.MissionID, host.NetworkID)
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	mine := findings[:0]
	for _, f := range findings {
		if f.HostID == host.ID {
			mine = append(mine, f)
		}
	}
	a.ok(w, map[string]any{
		"host": host, "services": services, "asset": asset, "findings": mine,
	})
}

func (a *API) handleListServices(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := store.ServiceFilter{
		MissionID: m.ID,
		NetworkID: queryInt64(r, "network_id"),
		HostID:    queryInt64(r, "host_id"),
		Port:      queryInt(r, "port", 0),
		Protocol:  model.Protocol(strings.ToLower(q.Get("protocol"))),
		Search:    q.Get("q"),
		Limit:     queryInt(r, "limit", 0),
		Offset:    queryInt(r, "offset", 0),
	}
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
	a.ok(w, services)
}

func (a *API) handleListFindings(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	findings, err := a.Store.ListFindings(r.Context(), m.ID, queryInt64(r, "network_id"))
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	a.ok(w, findings)
}

func (a *API) handleListAssets(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	assets, err := a.Store.ListAssets(r.Context(), m.ID)
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

func (a *API) handleUpdateAsset(w http.ResponseWriter, r *http.Request, u model.User) {
	asset, ok := a.requireAsset(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Label *string          `json:"label"`
		Notes *string          `json:"notes"`
		Tags  *[]string        `json:"tags"`
		Kind  *model.AssetKind `json:"kind"`
	}
	if !a.decode(w, r, &req) {
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
	results, err := a.Store.ListReach(r.Context(), m.ID, queryInt64(r, "source_network_id"))
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
	cells, err := a.Store.Matrix(r.Context(), m.ID)
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

	data, err := a.Store.MissionData(r.Context(), m.ID, networkID)
	if err != nil {
		a.failStore(w, err, "mission data")
		return
	}
	data.ExportedBy = u.Username

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
	a.audit(r, u, m.ID, "mission.exported", format)
}
