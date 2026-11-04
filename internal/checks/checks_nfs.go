package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"

	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("nfs-exports-world-readable", "NFS share exported to the whole world", model.SevHigh,
			[]string{"nfs", "mountd", "rpcbind", "sunrpc"},
			"The NFS server exports at least one share without restricting the client list, so any host able to reach port 2049 can mount it. NFSv3 trusts the UID and GID sent by the client, so an attacker who can mount a share reads and writes every file on it simply by claiming the right UID."),
		Remediation: "Restrict every entry in /etc/exports to the specific hosts or subnets that need it, never '*'. Export read-only where possible, keep root_squash enabled, and firewall ports 111/2049 (and the mountd port) to the storage network. Prefer NFSv4 with Kerberos (sec=krb5p) when the data is sensitive.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/284.html",
			"https://datatracker.ietf.org/doc/html/rfc1813",
		},
		HostLevel: true,
		Applies:   nfsApplies,
		Run:       runNFSWorldExport,
	})
	register(&Check{
		Info: checkInfo("nfs-exports-listable", "NFS export list readable by anyone", model.SevLow,
			[]string{"nfs", "mountd", "rpcbind", "sunrpc"},
			"The mountd service answers the MOUNTPROC3_EXPORT procedure to unauthenticated clients, revealing every exported path and the hosts allowed to mount it. This maps the storage layout and the trust relationships of the environment for an attacker."),
		Remediation: "Firewall rpcbind (111), mountd and NFS (2049) so that only NFS clients can reach them. On NFSv4-only servers, disable the MOUNT protocol and rpcbind entirely.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc1813#section-5.2.5",
		},
		HostLevel: true,
		Applies:   nfsApplies,
		Run:       runNFSExportList,
	})
}

// nfsApplies fires when any of the NFS-related RPC endpoints is open.
func nfsApplies(t *Target) bool {
	return t.HasPort(2049, model.TCP) || t.HasPort(111, model.TCP) || t.HasPort(20048, model.TCP)
}

// ONC RPC programs used here. Only read-only procedures are ever called.
const (
	progPortmap uint32 = 100000
	progMount   uint32 = 100005

	procPortmapGetPort uint32 = 3
	procMountExport    uint32 = 5

	ipprotoTCP uint32 = 6
)

// Bounds for parsing a hostile RPC reply.
const (
	maxRPCRecord    = 512 * 1024
	maxExports      = 512
	maxGroups       = 128
	maxXDRString    = 1024
	maxRPCFragments = 64 // fragments per reply
)

// nfsExport is one entry of a mountd EXPORT reply.
type nfsExport struct {
	Dir    string
	Groups []string
}

// World reports whether the export has no effective client restriction.
func (e nfsExport) World() bool {
	if len(e.Groups) == 0 {
		return true
	}
	for _, g := range e.Groups {
		switch strings.TrimSpace(g) {
		case "*", "", "0.0.0.0/0", "0.0.0.0", "::/0", "(everyone)":
			return true
		}
	}
	return false
}

func runNFSWorldExport(ctx context.Context, t *Target) []model.Finding {
	exports, port, err := nfsExports(ctx, t)
	if err != nil || len(exports) == 0 {
		return nil
	}
	var world []string
	for _, e := range exports {
		if e.World() {
			world = append(world, e.Dir)
		}
	}
	if len(world) == 0 {
		return nil
	}
	sort.Strings(world)
	ev := fmt.Sprintf("mountd on port %d exports %d share(s) with no client restriction:\n  %s",
		port, len(world), strings.Join(limitStrings(world, 25), "\n  "))
	return []model.Finding{t.FindingOn(2049, model.TCP, ev)}
}

func runNFSExportList(ctx context.Context, t *Target) []model.Finding {
	exports, port, err := nfsExports(ctx, t)
	if err != nil || len(exports) == 0 {
		return nil
	}
	lines := make([]string, 0, len(exports))
	for _, e := range exports {
		if len(e.Groups) == 0 {
			lines = append(lines, e.Dir+" -> (everyone)")
			continue
		}
		lines = append(lines, e.Dir+" -> "+strings.Join(limitStrings(e.Groups, 8), ", "))
	}
	sort.Strings(lines)
	ev := fmt.Sprintf("MOUNTPROC3_EXPORT answered on port %d without authentication:\n  %s",
		port, strings.Join(limitStrings(lines, 25), "\n  "))
	return []model.Finding{t.FindingOn(2049, model.TCP, ev)}
}

// nfsExports locates mountd (through rpcbind when available) and reads its
// export list. It returns the exports and the mountd port it used.
func nfsExports(ctx context.Context, t *Target) ([]nfsExport, int, error) {
	var errs []error
	for _, port := range nfsMountdPorts(ctx, t) {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		exports, err := mountExport(ctx, t, port)
		if err != nil {
			errs = append(errs, fmt.Errorf("mountd/%d: %w", port, err))
			continue
		}
		if len(exports) > 0 {
			return exports, port, nil
		}
	}
	return nil, 0, errors.Join(errs...)
}

// nfsMountdPorts lists the ports to try for mountd, best first: whatever
// rpcbind advertises, then the usual fixed ports.
func nfsMountdPorts(ctx context.Context, t *Target) []int {
	var ports []int
	seen := map[int]bool{}
	add := func(p int) {
		if p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if t.HasPort(111, model.TCP) {
		// Ask rpcbind where mountd listens. GETPORT is a lookup, not a write.
		for _, vers := range []uint32{3, 1} {
			if p, err := portmapGetPort(ctx, t, progMount, vers); err == nil {
				add(p)
			} else {
				t.Log.Debug("rpcbind getport failed", "vers", vers, "err", err)
			}
		}
	}
	add(20048) // Linux nfs-utils default when fixed
	add(2049)  // some appliances answer MOUNT on the NFS port itself
	if len(ports) > 4 {
		ports = ports[:4]
	}
	return ports
}

// portmapGetPort asks rpcbind for the TCP port of prog/vers.
func portmapGetPort(ctx context.Context, t *Target, prog, vers uint32) (int, error) {
	args := make([]byte, 16)
	binary.BigEndian.PutUint32(args[0:4], prog)
	binary.BigEndian.PutUint32(args[4:8], vers)
	binary.BigEndian.PutUint32(args[8:12], ipprotoTCP)
	binary.BigEndian.PutUint32(args[12:16], 0)

	body, err := rpcCall(ctx, t, 111, progPortmap, 2, procPortmapGetPort, args)
	if err != nil {
		return 0, err
	}
	x := &xdrReader{b: body}
	p, ok := x.u32()
	if !ok {
		return 0, errors.New("rpc: truncated GETPORT reply")
	}
	if p == 0 || p > 65535 {
		return 0, errors.New("rpc: program not registered")
	}
	return int(p), nil
}

// mountExport calls MOUNTPROC3_EXPORT, which takes no argument and only
// returns the export table: it mounts nothing and changes no state.
func mountExport(ctx context.Context, t *Target, port int) ([]nfsExport, error) {
	body, err := rpcCall(ctx, t, port, progMount, 3, procMountExport, nil)
	if err != nil {
		// Some servers only register MOUNT version 1.
		body, err = rpcCall(ctx, t, port, progMount, 1, procMountExport, nil)
		if err != nil {
			return nil, err
		}
	}
	return parseExportList(body)
}

// parseExportList decodes the XDR linked list returned by EXPORT. Every length
// is bounds checked and every list is capped: this parses hostile input.
func parseExportList(b []byte) ([]nfsExport, error) {
	x := &xdrReader{b: b}
	var out []nfsExport
	for len(out) < maxExports {
		more, ok := x.u32()
		if !ok {
			return out, errors.New("rpc: truncated export list")
		}
		if more == 0 {
			return out, nil
		}
		dir, ok := x.str(maxXDRString)
		if !ok {
			return out, errors.New("rpc: truncated export path")
		}
		e := nfsExport{Dir: sanitizeXDR(dir)}
		for len(e.Groups) < maxGroups {
			g, ok := x.u32()
			if !ok {
				return out, errors.New("rpc: truncated group list")
			}
			if g == 0 {
				break
			}
			name, ok := x.str(maxXDRString)
			if !ok {
				return out, errors.New("rpc: truncated group name")
			}
			e.Groups = append(e.Groups, sanitizeXDR(name))
		}
		out = append(out, e)
	}
	return out, nil
}

// sanitizeXDR makes a server-supplied string safe to put in a report.
func sanitizeXDR(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return truncate(strings.TrimSpace(s), 256)
}

// ---------------------------------------------------------------------------
// Minimal ONC RPC (RFC 5531) client over TCP, read-only procedures only
// ---------------------------------------------------------------------------

// rpcCall performs one AUTH_NULL RPC call and returns the result body.
func rpcCall(ctx context.Context, t *Target, port int, prog, vers, proc uint32, args []byte) ([]byte, error) {
	conn, err := t.DialPort(ctx, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	xid := rand.Uint32() //nolint:gosec // transaction id only, not a secret
	if _, err := conn.Write(rpcMessage(xid, prog, vers, proc, args)); err != nil {
		return nil, err
	}
	reply, err := readRPCRecord(conn)
	if err != nil {
		return nil, err
	}
	return parseRPCReply(reply, xid)
}

// rpcMessage builds a record-marked CALL with AUTH_NULL credentials.
func rpcMessage(xid, prog, vers, proc uint32, args []byte) []byte {
	body := make([]byte, 0, 40+len(args))
	put := func(v uint32) { body = binary.BigEndian.AppendUint32(body, v) }
	put(xid)
	put(0) // CALL
	put(2) // RPC version
	put(prog)
	put(vers)
	put(proc)
	put(0) // cred: AUTH_NULL
	put(0) // cred length
	put(0) // verf: AUTH_NULL
	put(0) // verf length
	body = append(body, args...)

	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body))|0x80000000) // last fragment
	return append(out, body...)
}

// readRPCRecord reassembles a record-marked reply, bounded in both fragment
// count and total size.
func readRPCRecord(r io.Reader) ([]byte, error) {
	var out []byte
	for i := 0; i < maxRPCFragments; i++ {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		h := binary.BigEndian.Uint32(hdr[:])
		n := int(h & 0x7fffffff)
		last := h&0x80000000 != 0
		if n < 0 || len(out)+n > maxRPCRecord {
			return nil, errors.New("rpc: record too large")
		}
		if n > 0 {
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			out = append(out, buf...)
		}
		if last {
			return out, nil
		}
	}
	return nil, errors.New("rpc: too many fragments")
}

// parseRPCReply validates the reply header and returns the result body.
func parseRPCReply(b []byte, wantXID uint32) ([]byte, error) {
	x := &xdrReader{b: b}
	xid, ok := x.u32()
	if !ok {
		return nil, errors.New("rpc: truncated reply")
	}
	if xid != wantXID {
		return nil, errors.New("rpc: transaction id mismatch")
	}
	mtype, ok := x.u32()
	if !ok || mtype != 1 {
		return nil, errors.New("rpc: not a reply")
	}
	replyStat, ok := x.u32()
	if !ok {
		return nil, errors.New("rpc: truncated reply status")
	}
	if replyStat != 0 {
		return nil, errors.New("rpc: call denied")
	}
	// Verifier: flavour + opaque body.
	if _, ok := x.u32(); !ok {
		return nil, errors.New("rpc: truncated verifier")
	}
	if _, ok := x.bytes(maxXDRString); !ok {
		return nil, errors.New("rpc: truncated verifier body")
	}
	acceptStat, ok := x.u32()
	if !ok {
		return nil, errors.New("rpc: truncated accept status")
	}
	if acceptStat != 0 {
		return nil, fmt.Errorf("rpc: accept status %d", acceptStat)
	}
	return x.rest(), nil
}

// xdrReader is a bounds-checked cursor over an XDR buffer. No method panics
// and none allocates from an attacker-controlled length without a cap.
type xdrReader struct {
	b   []byte
	off int
}

func (x *xdrReader) u32() (uint32, bool) {
	if x.off < 0 || x.off+4 > len(x.b) {
		x.off = len(x.b)
		return 0, false
	}
	v := binary.BigEndian.Uint32(x.b[x.off : x.off+4])
	x.off += 4
	return v, true
}

// bytes reads an opaque, length-prefixed, 4-byte-padded buffer.
func (x *xdrReader) bytes(max int) ([]byte, bool) {
	n, ok := x.u32()
	if !ok {
		return nil, false
	}
	if int64(n) > int64(max) || int64(n) > int64(len(x.b)-x.off) {
		x.off = len(x.b)
		return nil, false
	}
	start := x.off
	x.off += int(n)
	if pad := int(n) % 4; pad != 0 {
		skip := 4 - pad
		if x.off+skip > len(x.b) {
			x.off = len(x.b)
		} else {
			x.off += skip
		}
	}
	return x.b[start : start+int(n)], true
}

func (x *xdrReader) str(max int) (string, bool) {
	b, ok := x.bytes(max)
	if !ok {
		return "", false
	}
	return string(b), true
}

func (x *xdrReader) rest() []byte {
	if x.off >= len(x.b) {
		return nil
	}
	return x.b[x.off:]
}
