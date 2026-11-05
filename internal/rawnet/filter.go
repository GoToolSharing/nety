package rawnet

import (
	"fmt"
	"net/netip"

	"golang.org/x/net/bpf"
)

// IP protocol numbers used by the scanners.
const (
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// Ethernet types.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86dd
	EtherTypeVLAN = 0x8100
)

// FilterSpec describes which frames an AF_PACKET socket should receive. Filtering in the
// kernel keeps the receive path cheap at high packet rates.
type FilterSpec struct {
	// ARP accepts ARP frames (optionally only those whose target protocol address is
	// LocalIPv4).
	ARP bool
	// LocalIPv4 / LocalIPv6 restrict IP frames to this destination address (invalid = any
	// destination). A family with no protocol in IPv4Protos / IPv6Protos is rejected
	// entirely.
	LocalIPv4 netip.Addr
	LocalIPv6 netip.Addr
	// IPv4Protos / IPv6Protos list accepted IP protocol / next header values.
	IPv4Protos []uint8
	IPv6Protos []uint8
	// DropOutgoing rejects frames sent by this host (PACKET_OUTGOING) using the Linux
	// SKF_AD_PKTTYPE ancillary load.
	DropOutgoing bool
}

// snapLen is the number of bytes kept for an accepted frame.
const snapLen = 0x40000

// pktTypeOutgoing is PACKET_OUTGOING from linux/if_packet.h.
const pktTypeOutgoing = 4

// BuildFilter compiles spec into a classic BPF program.
func BuildFilter(spec FilterSpec) ([]bpf.Instruction, error) {
	var a asm
	if spec.DropOutgoing {
		a.emit(bpf.LoadExtension{Num: bpf.ExtType})
		a.jeq(pktTypeOutgoing, "drop", "")
	}
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	if spec.ARP {
		a.jeq(EtherTypeARP, "arp", "")
	}
	if len(spec.IPv4Protos) > 0 {
		a.jeq(EtherTypeIPv4, "v4", "")
	}
	if len(spec.IPv6Protos) > 0 {
		a.jeq(EtherTypeIPv6, "v6", "")
	}
	a.jmp("drop")

	if spec.ARP {
		a.label("arp")
		if spec.LocalIPv4.Is4() {
			b := spec.LocalIPv4.As4()
			a.emit(bpf.LoadAbsolute{Off: 14 + 24, Size: 4}) // ARP target protocol address
			a.jeq(be32(b[:]), "", "drop")
		}
		a.jmp("accept")
	}
	if len(spec.IPv4Protos) > 0 {
		a.label("v4")
		if spec.LocalIPv4.IsValid() {
			if !spec.LocalIPv4.Is4() {
				return nil, fmt.Errorf("rawnet: LocalIPv4 %s is not IPv4", spec.LocalIPv4)
			}
			b := spec.LocalIPv4.As4()
			a.emit(bpf.LoadAbsolute{Off: 14 + 16, Size: 4})
			a.jeq(be32(b[:]), "", "drop")
		}
		a.emit(bpf.LoadAbsolute{Off: 14 + 9, Size: 1})
		for _, p := range spec.IPv4Protos {
			a.jeq(uint32(p), "accept", "")
		}
		a.jmp("drop")
	}
	if len(spec.IPv6Protos) > 0 {
		a.label("v6")
		if spec.LocalIPv6.IsValid() {
			if !spec.LocalIPv6.Is6() || spec.LocalIPv6.Is4In6() {
				return nil, fmt.Errorf("rawnet: LocalIPv6 %s is not IPv6", spec.LocalIPv6)
			}
			b := spec.LocalIPv6.As16()
			for i := 0; i < 4; i++ {
				a.emit(bpf.LoadAbsolute{Off: uint32(14 + 24 + 4*i), Size: 4})
				a.jeq(be32(b[4*i:4*i+4]), "", "drop")
			}
		}
		a.emit(bpf.LoadAbsolute{Off: 14 + 6, Size: 1})
		for _, p := range spec.IPv6Protos {
			a.jeq(uint32(p), "accept", "")
		}
		a.jmp("drop")
	}
	a.label("accept")
	a.emit(bpf.RetConstant{Val: snapLen})
	a.label("drop")
	a.emit(bpf.RetConstant{Val: 0})
	return a.resolve()
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// asm is a tiny label-resolving assembler for classic BPF.
type asm struct {
	ins    []bpf.Instruction
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	idx           int
	skipTrue      string
	skipFalse     string
	unconditional bool
}

func (a *asm) emit(i bpf.Instruction) { a.ins = append(a.ins, i) }

func (a *asm) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.ins)
}

// jeq jumps to t when A == v, else to f ("" = fall through).
func (a *asm) jeq(v uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), skipTrue: t, skipFalse: f})
	a.ins = append(a.ins, bpf.JumpIf{Cond: bpf.JumpEqual, Val: v})
}

func (a *asm) jmp(to string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ins), skipTrue: to, unconditional: true})
	a.ins = append(a.ins, bpf.Jump{})
}

func (a *asm) resolve() ([]bpf.Instruction, error) {
	off := func(from int, label string) (uint32, error) {
		if label == "" {
			return 0, nil
		}
		to, ok := a.labels[label]
		if !ok {
			return 0, fmt.Errorf("rawnet: bpf label %q undefined", label)
		}
		d := to - from - 1
		if d < 0 {
			return 0, fmt.Errorf("rawnet: bpf backward jump to %q", label)
		}
		return uint32(d), nil
	}
	for _, f := range a.fixups {
		if f.unconditional {
			d, err := off(f.idx, f.skipTrue)
			if err != nil {
				return nil, err
			}
			a.ins[f.idx] = bpf.Jump{Skip: d}
			continue
		}
		t, err := off(f.idx, f.skipTrue)
		if err != nil {
			return nil, err
		}
		e, err := off(f.idx, f.skipFalse)
		if err != nil {
			return nil, err
		}
		if t > 255 || e > 255 {
			return nil, fmt.Errorf("rawnet: bpf jump too long")
		}
		j := a.ins[f.idx].(bpf.JumpIf)
		j.SkipTrue, j.SkipFalse = uint8(t), uint8(e)
		a.ins[f.idx] = j
	}
	return a.ins, nil
}
