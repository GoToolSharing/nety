// Command netydemo fills a NETY database with a realistic engagement so the
// platform can be shown without plugging into anyone's network.
//
//	go run ./cmd/netydemo -data ./demo-data
//	nety serve --data ./demo-data --no-tls --listen 127.0.0.1:8080
//
// Everything it writes is invented. The addresses are RFC 1918, the hostnames
// and the client name are made up, and nothing here was observed on a real
// network.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/GoToolSharing/nety/internal/auth"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"

	_ "modernc.org/sqlite"
)

func main() {
	dataDir := flag.String("data", "demo-data", "data directory to create the demo database in")
	user := flag.String("user", "demo", "username to create")
	pass := flag.String("password", "Demo-Password-1A", "password for it")
	reset := flag.Bool("reset", true, "delete any existing database first")
	flag.Parse()

	if err := run(*dataDir, *user, *pass, *reset); err != nil {
		fmt.Fprintln(os.Stderr, "netydemo: "+err.Error())
		os.Exit(1)
	}
}

func run(dataDir, username, password string, reset bool) error {
	if reset {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(filepath.Join(dataDir, "nety.db"+suffix))
		}
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "nety.db"), nil)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	rng := rand.New(rand.NewSource(20261104))

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	u, err := st.CreateUser(ctx, model.User{
		Username: username, DisplayName: "Demo operator",
		Role: model.RoleAdmin, PasswordHash: hash,
	})
	if err != nil {
		return err
	}

	m, err := st.CreateMission(ctx, model.Mission{
		Name:   "Revue de segmentation interne",
		Client: "Groupe Lumexa",
		Description: "Cartographie des VLAN du siège et vérification de leur cloisonnement. " +
			"Quatre points de raccordement testés, matrice de traversée en annexe.",
		ScopeCIDRs:   []string{"10.20.0.0/16"},
		ExcludeCIDRs: []string{"10.20.99.250/32"},
		CreatedBy:    u.ID,
	})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	nets, err := seedNetworks(ctx, st, m.ID, now)
	if err != nil {
		return err
	}
	if err := seedInventory(ctx, st, m.ID, nets, now, rng); err != nil {
		return err
	}
	// A second connection, used only to backdate the demo history.
	raw, err := sql.Open("sqlite", filepath.Join(dataDir, "nety.db"))
	if err != nil {
		return err
	}
	defer raw.Close()
	if err := seedScans(ctx, st, raw, m.ID, nets, u.ID, now); err != nil {
		return err
	}
	if err := seedReachability(ctx, st, m.ID, nets, now, rng); err != nil {
		return err
	}

	stats, _ := st.Stats(ctx)
	fmt.Printf("Demo mission ready in %s\n\n", dataDir)
	fmt.Printf("  mission   %s - %s\n", m.Name, m.Client)
	for _, k := range []string{"networks", "hosts", "services", "assets", "findings", "reach_results", "scans"} {
		fmt.Printf("  %-9s %d\n", k, stats[k])
	}
	fmt.Printf("\n  sign in as %s / %s\n", username, password)
	return nil
}

// ---------------------------------------------------------------------------
// networks
// ---------------------------------------------------------------------------

type demoNet struct {
	model.Network
	prefix string
}

func seedNetworks(ctx context.Context, st *store.Store, missionID int64, now time.Time) ([]demoNet, error) {
	captured := now.Add(-50 * time.Hour)
	defs := []struct {
		name, desc, iface, local, gw, prefix string
		vlan                                 int
		l2                                   model.L2Info
	}{
		{
			name: "Bureaux - étage 2", desc: "Prise murale salle de réunion B204.",
			iface: "eth0", local: "10.20.10.37", gw: "10.20.10.1", prefix: "10.20.10.0/24", vlan: 10,
			l2: model.L2Info{
				Neighbors: []model.L2Neighbor{{
					Protocol: "cdp", DeviceID: "SW-ACC-B2-01.lumexa.lan", PortID: "GigabitEthernet1/0/14",
					Platform: "cisco WS-C2960X-48FPS-L", Software: "IOS 15.2(7)E3",
					MgmtAddress: "10.20.99.11", NativeVLAN: 10, VoiceVLAN: 30,
					Capabilities: []string{"Switch", "IGMP"},
				}},
				NativeVLAN: 10, VoiceVLAN: 30, ObservedVLANs: []int{10, 30},
				STPRootBridge: "00:1b:0c:aa:11:02", CapturedAt: &captured,
			},
		},
		{
			name: "Serveurs", desc: "Port patché depuis la baie, salle technique.",
			iface: "eth0", local: "10.20.20.60", gw: "10.20.20.1", prefix: "10.20.20.0/24", vlan: 20,
			l2: model.L2Info{
				Neighbors: []model.L2Neighbor{{
					Protocol: "lldp", DeviceID: "SW-CORE-01", PortID: "Te1/0/3",
					Platform: "Aruba 6300M", Software: "ArubaOS-CX 10.11",
					MgmtAddress: "10.20.99.10", NativeVLAN: 20,
				}},
				NativeVLAN: 20, ObservedVLANs: []int{20}, CapturedAt: &captured,
			},
		},
		{
			name: "Téléphonie", desc: "Prise derrière le téléphone de l'accueil.",
			iface: "eth0", local: "10.20.30.88", gw: "10.20.30.1", prefix: "10.20.30.0/24", vlan: 30,
			l2: model.L2Info{
				DTPSeen: true, DTPMode: "desirable",
				Neighbors: []model.L2Neighbor{{
					Protocol: "cdp", DeviceID: "SW-ACC-RDC-02.lumexa.lan", PortID: "GigabitEthernet1/0/2",
					Platform: "cisco WS-C2960X-24PS-L", MgmtAddress: "10.20.99.12",
					NativeVLAN: 30, VoiceVLAN: 30,
				}},
				NativeVLAN: 30, VoiceVLAN: 30, ObservedVLANs: []int{10, 30}, CapturedAt: &captured,
			},
		},
		{
			name: "Management", desc: "Port d'administration, accès accordé pour l'audit.",
			iface: "eth0", local: "10.20.99.201", gw: "10.20.99.1", prefix: "10.20.99.0/24", vlan: 99,
			l2: model.L2Info{
				Neighbors: []model.L2Neighbor{{
					Protocol: "lldp", DeviceID: "SW-CORE-01", PortID: "Gi1/0/48",
					Platform: "Aruba 6300M", MgmtAddress: "10.20.99.10", NativeVLAN: 99,
				}},
				NativeVLAN: 99, ObservedVLANs: []int{99}, CapturedAt: &captured,
			},
		},
	}

	out := make([]demoNet, 0, len(defs))
	for _, d := range defs {
		n, err := st.CreateNetwork(ctx, model.Network{
			MissionID: missionID, Name: d.name, VLANID: d.vlan, Description: d.desc,
			Interface: d.iface, LocalIP: d.local, LocalMAC: "b8:27:eb:4f:12:9c",
			Prefixes: []string{d.prefix}, Gateway: d.gw,
			DNSServers:   []string{"10.20.20.10", "10.20.20.11"},
			DomainSearch: []string{"lumexa.lan"},
			DHCPServer:   d.gw,
			L2:           d.l2,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, demoNet{Network: n, prefix: d.prefix})
	}
	return out, nil
}
