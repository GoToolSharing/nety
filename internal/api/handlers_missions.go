package api

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/GoToolSharing/nety/internal/auth"
	"github.com/GoToolSharing/nety/internal/jobs"
	"github.com/GoToolSharing/nety/internal/model"
)

// ---------------------------------------------------------------------------
// missions
// ---------------------------------------------------------------------------

func (a *API) handleListMissions(w http.ResponseWriter, r *http.Request, u model.User) {
	missions, err := a.Store.ListMissions(r.Context(), u.ID, auth.IsAdmin(u))
	if err != nil {
		a.failStore(w, err, "missions")
		return
	}
	a.ok(w, missions)
}

func (a *API) handleCreateMission(w http.ResponseWriter, r *http.Request, u model.User) {
	var req struct {
		Name         string   `json:"name"`
		Client       string   `json:"client"`
		Description  string   `json:"description"`
		ScopeCIDRs   []string `json:"scope_cidrs"`
		ExcludeCIDRs []string `json:"exclude_cidrs"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		a.fail(w, http.StatusBadRequest, "invalid", "a mission name is required")
		return
	}
	if !a.validateCIDRs(w, req.ScopeCIDRs, "scope") || !a.validateCIDRs(w, req.ExcludeCIDRs, "exclusions") {
		return
	}
	m, err := a.Store.CreateMission(r.Context(), model.Mission{
		Name: req.Name, Client: req.Client, Description: req.Description,
		ScopeCIDRs: req.ScopeCIDRs, ExcludeCIDRs: req.ExcludeCIDRs, CreatedBy: u.ID,
	})
	if err != nil {
		a.failStore(w, err, "mission")
		return
	}
	a.audit(r, u, m.ID, "mission.created", m.Name)
	a.created(w, m)
}

func (a *API) handleGetMission(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	a.ok(w, m)
}

func (a *API) handleUpdateMission(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Name         *string   `json:"name"`
		Client       *string   `json:"client"`
		Description  *string   `json:"description"`
		ScopeCIDRs   *[]string `json:"scope_cidrs"`
		ExcludeCIDRs *[]string `json:"exclude_cidrs"`
		Archived     *bool     `json:"archived"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			a.fail(w, http.StatusBadRequest, "invalid", "a mission name is required")
			return
		}
		m.Name = strings.TrimSpace(*req.Name)
	}
	if req.Client != nil {
		m.Client = *req.Client
	}
	if req.Description != nil {
		m.Description = *req.Description
	}
	if req.ScopeCIDRs != nil {
		if !a.validateCIDRs(w, *req.ScopeCIDRs, "scope") {
			return
		}
		m.ScopeCIDRs = *req.ScopeCIDRs
	}
	if req.ExcludeCIDRs != nil {
		if !a.validateCIDRs(w, *req.ExcludeCIDRs, "exclusions") {
			return
		}
		m.ExcludeCIDRs = *req.ExcludeCIDRs
	}
	if req.Archived != nil {
		m.Archived = *req.Archived
	}
	if err := a.Store.UpdateMission(r.Context(), m); err != nil {
		a.failStore(w, err, "mission")
		return
	}
	a.audit(r, u, m.ID, "mission.updated", m.Name)
	a.ok(w, m)
}

func (a *API) handleDeleteMission(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	for _, id := range a.Runner.Running() {
		if sc, err := a.Store.Scan(r.Context(), id); err == nil && sc.MissionID == m.ID {
			a.fail(w, http.StatusConflict, "busy", "a scan is still running on this mission; stop it first")
			return
		}
	}
	if err := a.Store.DeleteMission(r.Context(), m.ID); err != nil {
		a.failStore(w, err, "mission")
		return
	}
	a.audit(r, u, 0, "mission.deleted", m.Name)
	a.ok(w, map[string]bool{"ok": true})
}

func (a *API) handleGetMembers(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	ids, err := a.Store.MissionMembers(r.Context(), m.ID)
	if err != nil {
		a.failStore(w, err, "members")
		return
	}
	// Return the people, not just their ids. Listing every account is an
	// administrator's privilege, so a plain operator had no way to turn these
	// ids into names and saw an empty team on a mission they are part of.
	// Who else is on your own mission is not a secret from you.
	members := make([]missionMember, 0, len(ids))
	for _, id := range ids {
		mu, err := a.Store.UserByID(r.Context(), id)
		if err != nil {
			continue // deleted meanwhile
		}
		members = append(members, missionMember{
			ID: mu.ID, Username: mu.Username, DisplayName: mu.DisplayName,
			Role: mu.Role, Disabled: mu.Disabled,
		})
	}
	a.ok(w, map[string]any{"user_ids": ids, "members": members})
}

// missionMember is the public view of someone on a mission: enough to show
// who they are, nothing more.
type missionMember struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        model.Role `json:"role"`
	Disabled    bool       `json:"disabled"`
}

func (a *API) handleSetMembers(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var req struct {
		UserIDs []int64 `json:"user_ids"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := a.Store.SetMissionMembers(r.Context(), m.ID, req.UserIDs); err != nil {
		a.failStore(w, err, "members")
		return
	}
	a.audit(r, u, m.ID, "mission.members_updated", "")
	a.ok(w, map[string]any{"user_ids": req.UserIDs})
}

// handleMissionSummary powers the overview screen in one round trip.
func (a *API) handleMissionSummary(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	ctx := r.Context()
	networks, err := a.Store.ListNetworks(ctx, m.ID)
	if err != nil {
		a.failStore(w, err, "networks")
		return
	}
	hosts, err := a.Store.ListHosts(ctx, m.ID, 0)
	if err != nil {
		a.failStore(w, err, "hosts")
		return
	}
	services, err := a.Store.ListServices(ctx, storeServiceFilter(m.ID, 0))
	if err != nil {
		a.failStore(w, err, "services")
		return
	}
	findings, err := a.Store.ListFindings(ctx, m.ID, 0)
	if err != nil {
		a.failStore(w, err, "findings")
		return
	}
	assets, err := a.Store.ListAssets(ctx, m.ID)
	if err != nil {
		a.failStore(w, err, "assets")
		return
	}
	matrix, err := a.Store.Matrix(ctx, m.ID)
	if err != nil {
		a.failStore(w, err, "matrix")
		return
	}
	scans, err := a.Store.ListScans(ctx, m.ID, 20)
	if err != nil {
		a.failStore(w, err, "scans")
		return
	}

	perNetwork := map[int64]map[string]int{}
	touch := func(id int64) map[string]int {
		v := perNetwork[id]
		if v == nil {
			v = map[string]int{}
			perNetwork[id] = v
		}
		return v
	}
	for _, n := range networks {
		touch(n.ID)
	}
	for _, h := range hosts {
		touch(h.NetworkID)["hosts"]++
	}
	for _, s := range services {
		touch(s.NetworkID)["services"]++
	}
	severities := map[model.Severity]int{}
	for _, f := range findings {
		severities[f.Severity]++
		touch(f.NetworkID)["findings"]++
	}
	crossed := 0
	for _, c := range matrix {
		if c.Reachable > 0 {
			crossed++
		}
	}

	a.ok(w, map[string]any{
		"mission":      m,
		"networks":     networks,
		"per_network":  perNetwork,
		"hosts":        len(hosts),
		"services":     len(services),
		"assets":       len(assets),
		"findings":     len(findings),
		"by_severity":  severities,
		"matrix_cells": len(matrix),
		"crossed":      crossed,
		"recent_scans": scans,
	})
}

// ---------------------------------------------------------------------------
// networks
// ---------------------------------------------------------------------------

func (a *API) handleListNetworks(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	networks, err := a.Store.ListNetworks(r.Context(), m.ID)
	if err != nil {
		a.failStore(w, err, "networks")
		return
	}
	a.ok(w, networks)
}

func (a *API) handleCreateNetwork(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var n model.Network
	if !a.decode(w, r, &n) {
		return
	}
	n.ID = 0
	n.MissionID = m.ID
	if strings.TrimSpace(n.Name) == "" {
		a.fail(w, http.StatusBadRequest, "invalid", "a network name is required")
		return
	}
	if n.VLANID < 0 || n.VLANID > 4094 {
		a.fail(w, http.StatusBadRequest, "invalid", "VLAN id must be between 1 and 4094")
		return
	}
	if !a.validateCIDRs(w, n.Prefixes, "prefixes") {
		return
	}
	saved, err := a.Store.CreateNetwork(r.Context(), n)
	if err != nil {
		a.failStore(w, err, "network")
		return
	}
	a.audit(r, u, m.ID, "network.created", saved.Name)
	a.Bus.PublishData(model.EvtNetwork, m.ID, 0, saved)
	a.created(w, saved)
}

// requireNetwork loads a network and checks mission access.
func (a *API) requireNetwork(w http.ResponseWriter, r *http.Request, u model.User) (model.Network, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Network{}, false
	}
	n, err := a.Store.Network(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "network")
		return model.Network{}, false
	}
	if _, ok := a.missionByID(w, r, u, n.MissionID); !ok {
		return model.Network{}, false
	}
	return n, true
}

func (a *API) handleGetNetwork(w http.ResponseWriter, r *http.Request, u model.User) {
	n, ok := a.requireNetwork(w, r, u)
	if !ok {
		return
	}
	a.ok(w, n)
}

func (a *API) handleUpdateNetwork(w http.ResponseWriter, r *http.Request, u model.User) {
	n, ok := a.requireNetwork(w, r, u)
	if !ok {
		return
	}
	var req struct {
		Name         *string   `json:"name"`
		VLANID       *int      `json:"vlan_id"`
		Description  *string   `json:"description"`
		Interface    *string   `json:"interface"`
		LocalIP      *string   `json:"local_ip"`
		LocalMAC     *string   `json:"local_mac"`
		Prefixes     *[]string `json:"prefixes"`
		Gateway      *string   `json:"gateway"`
		DNSServers   *[]string `json:"dns_servers"`
		DomainSearch *[]string `json:"domain_search"`
		DHCPServer   *string   `json:"dhcp_server"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Name != nil {
		n.Name = strings.TrimSpace(*req.Name)
	}
	if req.VLANID != nil {
		if *req.VLANID < 0 || *req.VLANID > 4094 {
			a.fail(w, http.StatusBadRequest, "invalid", "VLAN id must be between 1 and 4094")
			return
		}
		n.VLANID = *req.VLANID
	}
	if req.Description != nil {
		n.Description = *req.Description
	}
	if req.Interface != nil {
		n.Interface = *req.Interface
	}
	if req.LocalIP != nil {
		n.LocalIP = *req.LocalIP
	}
	if req.LocalMAC != nil {
		n.LocalMAC = *req.LocalMAC
	}
	if req.Prefixes != nil {
		if !a.validateCIDRs(w, *req.Prefixes, "prefixes") {
			return
		}
		n.Prefixes = *req.Prefixes
	}
	if req.Gateway != nil {
		n.Gateway = *req.Gateway
	}
	if req.DNSServers != nil {
		n.DNSServers = *req.DNSServers
	}
	if req.DomainSearch != nil {
		n.DomainSearch = *req.DomainSearch
	}
	if req.DHCPServer != nil {
		n.DHCPServer = *req.DHCPServer
	}
	if err := a.Store.UpdateNetwork(r.Context(), n); err != nil {
		a.failStore(w, err, "network")
		return
	}
	a.audit(r, u, n.MissionID, "network.updated", n.Name)
	a.Bus.PublishData(model.EvtNetwork, n.MissionID, 0, n)
	a.ok(w, n)
}

func (a *API) handleDeleteNetwork(w http.ResponseWriter, r *http.Request, u model.User) {
	n, ok := a.requireNetwork(w, r, u)
	if !ok {
		return
	}
	if err := a.Store.DeleteNetwork(r.Context(), n.ID); err != nil {
		a.failStore(w, err, "network")
		return
	}
	a.audit(r, u, n.MissionID, "network.deleted", n.Name)
	a.ok(w, map[string]bool{"ok": true})
}

// handleInterfaces lists the local NICs so the operator can pick one.
func (a *API) handleInterfaces(w http.ResponseWriter, r *http.Request, _ model.User) {
	if a.Engines.NetInspector == nil {
		a.engineMissing(w, "interface inspection")
		return
	}
	ifaces, err := a.Engines.NetInspector.Interfaces()
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	a.ok(w, ifaces)
}

// handleDetectNetwork inspects the current attachment and returns a draft
// network the operator can review before saving.
func (a *API) handleDetectNetwork(w http.ResponseWriter, r *http.Request, _ model.User) {
	if a.Engines.NetInspector == nil {
		a.engineMissing(w, "network detection")
		return
	}
	var req struct {
		Interface string `json:"interface"`
	}
	if r.ContentLength > 0 && !a.decode(w, r, &req) {
		return
	}
	nc, err := a.Engines.NetInspector.Detect(r.Context(), req.Interface)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	draft := model.Network{
		Interface: nc.Interface,
		Prefixes:  jobs.PrefixStrings(nc.Prefixes),
	}
	if nc.LocalIP.IsValid() {
		draft.LocalIP = nc.LocalIP.String()
	}
	if len(nc.LocalMAC) > 0 {
		draft.LocalMAC = nc.LocalMAC.String()
	}
	if nc.Gateway.IsValid() {
		draft.Gateway = nc.Gateway.String()
	}
	if nc.DHCPServer.IsValid() {
		draft.DHCPServer = nc.DHCPServer.String()
	}
	for _, d := range nc.DNSServers {
		draft.DNSServers = append(draft.DNSServers, d.String())
	}
	draft.DomainSearch = nc.DomainSearch
	a.ok(w, draft)
}

// validateCIDRs rejects malformed network specifications early, with a message
// naming the offending entry.
func (a *API) validateCIDRs(w http.ResponseWriter, list []string, what string) bool {
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			if _, err := netip.ParsePrefix(v); err != nil {
				a.fail(w, http.StatusBadRequest, "invalid", what+": invalid CIDR "+v)
				return false
			}
			continue
		}
		if _, err := netip.ParseAddr(v); err != nil {
			if _, err := jobs.ParseTargets([]string{v}); err != nil {
				a.fail(w, http.StatusBadRequest, "invalid", what+": invalid value "+v)
				return false
			}
		}
	}
	return true
}
