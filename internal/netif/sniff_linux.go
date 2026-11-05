//go:build linux

package netif

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/GoToolSharing/nety/internal/model"
)

// SniffL2 passively listens on iface for dur and decodes the switch-port control plane:
// CDP and LLDP neighbour announcements, DTP (does the port offer to negotiate a trunk?),
// STP (which bridge is root) and any 802.1Q tag seen on the wire.
//
// It is strictly passive: the socket is opened for reading only and NETY transmits
// nothing. The interface is put in promiscuous mode for the duration and taken out of it
// before returning.
func (n *Inspector) SniffL2(ctx context.Context, iface string, dur time.Duration) (model.L2Info, error) {
	if dur <= 0 {
		dur = 30 * time.Second
	}
	name := iface
	if name == "" {
		idx, _, ok := defaultRoute()
		if !ok {
			return model.L2Info{}, errors.New("netif: no default route; pass an explicit interface")
		}
		l, err := net.InterfaceByIndex(idx)
		if err != nil {
			return model.L2Info{}, fmt.Errorf("netif: interface %d: %w", idx, err)
		}
		name = l.Name
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return model.L2Info{}, fmt.Errorf("netif: interface %q: %w", name, err)
	}

	cfg := &packet.Config{}
	if prog, err := controlPlaneFilter(); err == nil {
		cfg.Filter = prog
	} else {
		n.log.Debug("netif: BPF filter unavailable, capturing unfiltered", "err", err)
	}
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, cfg)
	if err != nil {
		return model.L2Info{}, fmt.Errorf("netif: AF_PACKET on %q: %w", name, mapPermErr(err))
	}
	defer conn.Close()

	if err := conn.SetPromiscuous(true); err != nil {
		n.log.Warn("netif: promiscuous mode refused, capturing anyway", "iface", name, "err", err)
	} else {
		defer func() { _ = conn.SetPromiscuous(false) }()
	}

	col := NewL2Collector()
	deadline := time.Now().Add(dur)
	_ = conn.SetReadDeadline(deadline)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()

	buf := make([]byte, 1<<16)
	for {
		nbytes, _, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			n.log.Debug("netif: capture read error", "iface", name, "err", err)
			break
		}
		col.Consume(buf[:nbytes])
	}

	info := col.Info(time.Now())
	n.log.Info("netif: L2 capture finished",
		"iface", name, "duration", dur, "frames", col.Frames(),
		"neighbors", len(info.Neighbors), "dtp", info.DTPSeen, "vlans", len(info.ObservedVLANs))
	return info, nil
}

// controlPlaneFilter keeps only what the collector can decode: LLDP, VLAN tagged frames
// (for ObservedVLANs) and 802.3/LLC frames (CDP, DTP, STP). Everything else, the bulk of
// the traffic on a busy port, is dropped in the kernel.
func controlPlaneFilter() ([]bpf.RawInstruction, error) {
	const snaplen = 1 << 16
	return bpf.Assemble([]bpf.Instruction{
		// A = ethertype / length field
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeLLDP, SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeDot1Q, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeQinQ, SkipTrue: 1},
		// Not one of the above: accept only 802.3 length fields (<= 1500).
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 1500, SkipTrue: 1},
		bpf.RetConstant{Val: snaplen},
		bpf.RetConstant{Val: 0},
	})
}
