package fingerprint

import (
	"bufio"
	"context"
	"errors"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/GoToolSharing/nety/internal/model"
)

// sshClientIdent is the identification string NETY presents. It must start with
// "SSH-2.0-"; a conventional value keeps picky servers happy.
const sshClientIdent = "SSH-2.0-OpenSSH_9.6"

// sshProbeUser is the (non-existent) account used for the "none" probe. No credential is
// ever sent: the request only makes the server disclose which authentication methods it
// would accept.
const sshProbeUser = "nety-audit"

// maxHostKeyAlgos bounds how many extra handshakes we open to collect host keys (one
// connection per algorithm).
const maxHostKeyAlgos = 6

// errStopAuth aborts the x/crypto/ssh handshake right after the server answered the
// "none" authentication request.
var errStopAuth = errors.New("fingerprint: ssh auth probe done")

// probeSSH collects everything observable from an SSH server without authenticating: the
// identification banner, the offered algorithms, the host keys and the accepted
// authentication methods.
func (f *fingerprinter) probeSSH(ctx context.Context, d *dialer, banner []byte) *model.SSHInfo {
	info := &model.SSHInfo{Banner: cleanText(string(banner))}

	ident, kex, err := d.sshAlgorithms(ctx)
	if err != nil {
		f.log.Debug("ssh kexinit probe failed", "target", d.addr(), "err", err)
	}
	if ident != "" {
		info.Banner = cleanText(ident)
	}
	if kex != nil {
		info.KexAlgos = boundedList(kex.KexAlgos, 64)
		info.Ciphers = boundedList(kex.CiphersS2C, 64)
		info.MACs = boundedList(kex.MACsS2C, 64)
	}

	for i, algo := range sshHostKeyAlgos(kex) {
		if err := ctx.Err(); err != nil {
			break
		}
		key, methods, none, err := d.sshHostKey(ctx, algo)
		if err != nil && key == nil {
			f.log.Debug("ssh host key probe failed", "target", d.addr(), "algo", algo, "err", err)
			continue
		}
		if key != nil {
			hk := model.SSHHostKey{Type: key.Type(), SHA256: ssh.FingerprintSHA256(key)}
			if !slices.ContainsFunc(info.HostKeys, func(o model.SSHHostKey) bool {
				return o.SHA256 == hk.SHA256
			}) {
				info.HostKeys = append(info.HostKeys, hk)
			}
		}
		if len(info.AuthMeth) == 0 {
			if none {
				info.AuthMeth = []string{"none"}
			} else {
				info.AuthMeth = boundedList(methods, 16)
			}
		}
		// One successful handshake is enough when the server advertised no algorithm list
		// we could read.
		if kex == nil && i == 0 {
			break
		}
	}
	return info
}

// sshAlgorithms reads the server identification string and its KEXINIT, which lists every
// algorithm the server is willing to use. This is done on a raw connection: the exchange
// is unencrypted up to that point.
func (d *dialer) sshAlgorithms(ctx context.Context) (string, *kexInit, error) {
	c, err := d.dial(ctx)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(capDuration(d.timeout, 10*time.Second))); err != nil {
		return "", nil, err
	}

	br := bufio.NewReaderSize(c, 8192)
	ident, _, err := readSSHIdent(br)
	if err != nil {
		return "", nil, err
	}
	if _, err := c.Write([]byte(sshClientIdent + "\r\n")); err != nil {
		return ident, nil, err
	}
	// The server sends KEXINIT first (possibly after a few other packets).
	for range 4 {
		p, err := readSSHPlainPacket(br)
		if err != nil {
			return ident, nil, err
		}
		if len(p) > 0 && p[0] == sshMsgKexInit {
			k, err := parseKexInit(p)
			return ident, k, err
		}
	}
	return ident, nil, errors.New("ssh: no KEXINIT received")
}

// sshHostKey performs a full key exchange restricted to one host key algorithm, captures
// the presented key, then asks for the "none" authentication method to learn which
// methods the server accepts. It never sends a credential. none reports that "none" was
// ACCEPTED, i.e. the server grants access without authentication.
func (d *dialer) sshHostKey(ctx context.Context, algo string) (key ssh.PublicKey, methods []string, none bool, err error) {
	cfg := &ssh.ClientConfig{
		Config:        permissiveSSHConfig(),
		User:          sshProbeUser,
		ClientVersion: sshClientIdent,
		Timeout:       capDuration(d.timeout, 10*time.Second),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return nil
		},
		BannerCallback: func(string) error { return nil },
		AuthCallback: func(actx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			methods = slices.Clone(actx.AllowedMethods)
			return nil, errStopAuth
		},
	}
	if algo != "" {
		cfg.HostKeyAlgorithms = []string{algo}
	}

	conn, err := d.dial(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = conn.Close() }()

	cc, chans, reqs, err := ssh.NewClientConn(conn, d.addr(), cfg)
	if cc != nil {
		// "none" authentication succeeded: the server is wide open.
		none = true
		go ssh.DiscardRequests(reqs)
		go func() {
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "")
			}
		}()
		_ = cc.Close()
		return key, []string{"none"}, true, nil
	}
	if errors.Is(err, errStopAuth) {
		err = nil
	}
	return key, methods, none, err
}

// sshHostKeyAlgos picks the host key algorithms worth asking for: those the server
// advertised and this build can verify, certificates excluded.
func sshHostKeyAlgos(k *kexInit) []string {
	if k == nil || len(k.HostKeyAlgos) == 0 {
		return []string{""} // let x/crypto negotiate whatever it prefers
	}
	known := make(map[string]bool)
	for _, a := range ssh.SupportedAlgorithms().HostKeys {
		known[a] = true
	}
	for _, a := range ssh.InsecureAlgorithms().HostKeys {
		known[a] = true
	}
	var out []string
	for _, a := range k.HostKeyAlgos {
		if len(out) >= maxHostKeyAlgos {
			break
		}
		if strings.Contains(a, "-cert-") || !known[a] || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// permissiveSSHConfig accepts every algorithm this build knows, including the insecure
// legacy ones: the goal is to observe old servers, not to protect a session.
func permissiveSSHConfig() ssh.Config {
	sup, ins := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	return ssh.Config{
		KeyExchanges: mergeUnique(sup.KeyExchanges, ins.KeyExchanges),
		Ciphers:      mergeUnique(sup.Ciphers, ins.Ciphers),
		MACs:         mergeUnique(sup.MACs, ins.MACs),
	}
}

func mergeUnique(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, v := range l {
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return out
}

func boundedList(in []string, max int) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(in), max))
	for _, v := range in {
		if len(out) >= max {
			break
		}
		v = truncate(cleanText(v), 128)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Identification string → product / version
// ---------------------------------------------------------------------------

type sshIdentRule struct {
	re      *regexp.Regexp
	product string
	cpe     string // version appended when captured
	ostype  string
}

var sshIdentRules = []sshIdentRule{
	{regexp.MustCompile(`^OpenSSH_for_Windows_([\w.]+)`), "OpenSSH for_Windows", "cpe:/a:openbsd:openssh", "Windows"},
	{regexp.MustCompile(`^OpenSSH[_-]([\w.]+)`), "OpenSSH", "cpe:/a:openbsd:openssh", ""},
	{regexp.MustCompile(`^dropbear[_-]?([\w.]+)?`), "Dropbear sshd", "cpe:/a:matt_johnston:dropbear_ssh_server", ""},
	{regexp.MustCompile(`^libssh[_-]?([\w.]+)?`), "libssh", "cpe:/a:libssh:libssh", ""},
	{regexp.MustCompile(`^libssh2[_-]?([\w.]+)?`), "libssh2", "cpe:/a:libssh2:libssh2", ""},
	{regexp.MustCompile(`^ROSSSH`), "MikroTik RouterOS sshd", "cpe:/o:mikrotik:routeros", "RouterOS"},
	{regexp.MustCompile(`^mod_sftp[/_]?([\w.]+)?`), "ProFTPD mod_sftp", "cpe:/a:proftpd:proftpd", ""},
	{regexp.MustCompile(`^Cisco-([\w.]+)`), "Cisco SSH", "cpe:/o:cisco:ios", "IOS"},
	{regexp.MustCompile(`^SSHD-CORE-([\w.]+)`), "Apache Mina SSHD", "cpe:/a:apache:mina", ""},
	{regexp.MustCompile(`^Go$|^Go;`), "Go x/crypto/ssh", "", ""},
	{regexp.MustCompile(`^paramiko[_-]?([\w.]+)?`), "Paramiko", "cpe:/a:paramiko:paramiko", ""},
	{regexp.MustCompile(`^Erlang[/_]?([\w.]+)?`), "Erlang SSH", "", ""},
	{regexp.MustCompile(`^WeOnlyDo[\s-]?([\w.]+)?`), "WeOnlyDo sshd", "", ""},
	{regexp.MustCompile(`^CompleteFTP[_-]?([\w.]+)?`), "CompleteFTP sshd", "", "Windows"},
	{regexp.MustCompile(`^(?:SSHD|ssh)-([\w.]+)-Tectia`), "Tectia SSH", "cpe:/a:ssh:tectia_server", ""},
	{regexp.MustCompile(`^Serv-U[_-]?([\w.]+)?`), "Serv-U sshd", "cpe:/a:serv-u:serv-u", "Windows"},
	{regexp.MustCompile(`^VShell[_-]?([\w.]+)?`), "VanDyke VShell sshd", "", ""},
	{regexp.MustCompile(`^FortiSSH[_-]?([\w.]+)?`), "Fortinet FortiGate sshd", "cpe:/h:fortinet:fortigate", "FortiOS"},
	{regexp.MustCompile(`^PaloAltoNetworks`), "Palo Alto Networks sshd", "", "PAN-OS"},
	{regexp.MustCompile(`^RomSShell[_-]?([\w.]+)?`), "Allegro RomSShell", "cpe:/a:allegrosoft:romsshell", ""},
	{regexp.MustCompile(`^lancom`), "LANCOM sshd", "", ""},
	{regexp.MustCompile(`^AWS_SFTP[_-]?([\w.]+)?`), "AWS Transfer Family sftp", "", ""},
	{regexp.MustCompile(`^GerritCodeReview[_\s-]?([\w.]+)?`), "Gerrit Code Review sshd", "", ""},
	{regexp.MustCompile(`^Bitvise[\s_-]?(?:SSH\s+Server\s+)?\(?([\w.]+)?`), "Bitvise SSH Server", "", "Windows"},
	{regexp.MustCompile(`^CrushFTP`), "CrushFTP sshd", "", ""},
	{regexp.MustCompile(`^Huawei`), "Huawei VRP sshd", "", "VRP"},
}

// sshIdent is what an SSH identification string discloses.
type sshIdent struct {
	Product string
	Version string
	Extra   string // nmap-style extrainfo, e.g. "Ubuntu Linux; protocol 2.0"
	OS      string
	CPEs    []string
}

// sshIdentRe splits "SSH-<protoversion>-<software> <comments>".
var sshIdentRe = regexp.MustCompile(`^SSH-([\d.]+)-(\S*)(?:\s+(.*))?$`)

// distroHints maps a vendor comment to the label and OS nmap would report.
var distroHints = []struct{ needle, label, os string }{
	{"ubuntu", "Ubuntu Linux", "Linux"},
	{"debian", "Debian", "Linux"},
	{"raspbian", "Raspbian Linux", "Linux"},
	{"el7", "Red Hat Enterprise Linux", "Linux"},
	{"el8", "Red Hat Enterprise Linux", "Linux"},
	{"el9", "Red Hat Enterprise Linux", "Linux"},
	{"centos", "CentOS Linux", "Linux"},
	{"fc", "Fedora Linux", "Linux"},
	{"suse", "SUSE Linux", "Linux"},
	{"freebsd", "FreeBSD", "FreeBSD"},
	{"openbsd", "OpenBSD", "OpenBSD"},
	{"netbsd", "NetBSD", "NetBSD"},
	{"sunssh", "Solaris", "Solaris"},
	{"cisco", "Cisco", "IOS"},
}

// parseSSHIdent derives product, version, extra info, OS and CPEs from an SSH
// identification string, following nmap's conventions: the vendor comment is folded into
// the version and summarised in the extra info, so "SSH-2.0-OpenSSH_8.9p1
// Ubuntu-3ubuntu0.6" yields product "OpenSSH", version "8.9p1 Ubuntu-3ubuntu0.6" and
// extra "Ubuntu Linux; protocol 2.0".
func parseSSHIdent(ident string) sshIdent {
	var out sshIdent
	m := sshIdentRe.FindStringSubmatch(strings.TrimSpace(cleanText(ident)))
	if m == nil {
		return out
	}
	protoVer, software, comment := m[1], m[2], strings.TrimSpace(m[3])

	for _, r := range sshIdentRules {
		sm := r.re.FindStringSubmatch(software)
		if sm == nil {
			continue
		}
		out.Product = r.product
		if len(sm) > 1 {
			out.Version = sm[1]
		}
		out.OS = r.ostype
		if r.cpe != "" {
			c := r.cpe
			if out.Version != "" {
				c += ":" + out.Version
			}
			out.CPEs = append(out.CPEs, c)
		}
		break
	}
	if out.Product == "" {
		// Unknown implementation: keep the software token as-is.
		if name, ver, ok := strings.Cut(software, "_"); ok && ver != "" {
			out.Product, out.Version = name, ver
		} else {
			out.Product = software
		}
	}

	var label string
	if comment != "" {
		low := strings.ToLower(comment)
		for _, h := range distroHints {
			if strings.Contains(low, h.needle) {
				label = h.label
				if out.OS == "" {
					out.OS = h.os
				}
				break
			}
		}
		if out.Version != "" {
			out.Version += " " + comment
		} else {
			out.Version = comment
		}
	}
	if out.OS == "" {
		low := strings.ToLower(ident)
		for _, h := range osHints {
			if strings.Contains(low, h.needle) {
				out.OS = h.os
				break
			}
		}
	}

	out.Extra = "protocol " + protoVer
	if label != "" {
		out.Extra = label + "; " + out.Extra
	}
	out.Product = truncate(cleanText(out.Product), 128)
	out.Version = truncate(cleanText(out.Version), 96)
	out.Extra = truncate(cleanText(out.Extra), 200)
	return out
}
