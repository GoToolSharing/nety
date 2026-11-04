//go:build !linux

package netif

import (
	"context"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// Interfaces needs netlink.
func (n *Inspector) Interfaces() ([]engine.InterfaceInfo, error) {
	return nil, errUnsupportedf("enumerate interfaces")
}

// Detect needs netlink.
func (n *Inspector) Detect(ctx context.Context, iface string) (engine.NetContext, error) {
	return engine.NetContext{}, errUnsupportedf("detect network context for %q", iface)
}

// SniffL2 needs AF_PACKET.
func (n *Inspector) SniffL2(ctx context.Context, iface string, dur time.Duration) (model.L2Info, error) {
	_ = dur
	return model.L2Info{}, errUnsupportedf("sniff L2 on %q", iface)
}
