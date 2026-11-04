package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/identity/ntlm"
	"github.com/vaadata/nety/internal/identity/smb"
	"github.com/vaadata/nety/internal/model"
)

var smbServiceNames = []string{"microsoft-ds", "netbios-ssn", "smb", "cifs", "samba"}

// smbApplies selects the SMB service to test: 445, or 139 only when 445 is
// not open (avoids duplicate findings for the same server).
func smbApplies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP {
		return false
	}
	if s.Port == 445 {
		return true
	}
	if s.Port == 139 {
		return !t.HasPort(445, model.TCP)
	}
	return svcIs(s, model.TCP, smbServiceNames) && s.Port != 139 && s.Port != 445 && !t.HasPort(445, model.TCP) && !t.HasPort(139, model.TCP)
}

func init() {
	register(&Check{
		Info: partAInfo("smb-signing-not-required", "SMB signing not required", model.SevMedium,
			[]string{"microsoft-ds", "netbios-ssn"},
			"The SMB server does not require message signing. An attacker in a man-in-the-middle position can relay captured NTLM authentications to this host (NTLM relay, e.g. ntlmrelayx) and execute commands or access data with the relayed user's privileges."),
		Remediation: "Enable 'Microsoft network server: Digitally sign communications (always)' via GPO on every Windows host (RequireSecuritySignature=1), or 'server signing = mandatory' on Samba.",
		References:  []string{"https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always", "https://attack.mitre.org/techniques/T1557/001/"},
		Applies:     smbApplies,
		Run:         runSMBSigning,
	})
	register(&Check{
		Info: partAInfo("smbv1-enabled", "SMBv1 protocol enabled", model.SevMedium,
			[]string{"microsoft-ds", "netbios-ssn"},
			"The server accepts the obsolete SMBv1 (NT LM 0.12) dialect. SMBv1 lacks modern security features and is the attack surface of critical wormable vulnerabilities (MS17-010 EternalBlue, MS08-067 era bugs)."),
		Remediation: "Disable SMBv1 on the server (Set-SmbServerConfiguration -EnableSMB1Protocol $false, or 'server min protocol = SMB2' on Samba) after checking legacy client dependencies.",
		References:  []string{"https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"},
		Applies:     smbApplies,
		Run:         runSMBv1,
	})
	register(&Check{
		Info: partAInfo("smb-null-session", "SMB null session allows enumeration", model.SevMedium,
			[]string{"microsoft-ds", "netbios-ssn"},
			"An anonymous (null) SMB session can be established and used to enumerate information (shares through the srvsvc RPC interface) without any credentials."),
		Remediation: "Restrict anonymous access: set RestrictAnonymous=1/RestrictNullSessAccess=1, 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled, and remove entries from NullSessionShares/NullSessionPipes. On Samba set 'restrict anonymous = 2' and 'map to guest = never'.",
		References:  []string{"https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares"},
		Applies:     smbApplies,
		Run:         func(ctx context.Context, t *Target) []model.Finding { return runSMBSessionCheck(ctx, t, nil) },
	})
	register(&Check{
		Info: partAInfo("smb-guest-access", "SMB guest access allowed", model.SevMedium,
			[]string{"microsoft-ds", "netbios-ssn"},
			"The server accepts guest logons (the Guest account with an empty password, or unknown user names mapped to guest). Anyone on the network can open an SMB session and use resources granted to Everyone/Guests."),
		Remediation: "Disable the Guest account, disable insecure guest logons (AllowInsecureGuestAuth=0) and set 'map to guest = never' on Samba.",
		References:  []string{"https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default"},
		Applies:     smbApplies,
		Run:         runSMBGuest,
	})
	register(&Check{
		Info: partAInfo("smb-anonymous-share-access", "SMB share readable without credentials", model.SevHigh,
			[]string{"microsoft-ds", "netbios-ssn"},
			"At least one disk share can be opened and listed without valid credentials (null or guest session). Its content is readable by anyone on the network and frequently contains sensitive files (scripts, backups, credentials)."),
		Remediation: "Remove Everyone/Guest/ANONYMOUS LOGON permissions from the share and NTFS ACLs, disable guest access, and review the share content for exposed secrets.",
		References:  []string{"https://attack.mitre.org/techniques/T1039/"},
		Applies:     func(*Target) bool { return false }, // findings are raised by smb-null-session / smb-guest-access
		Run:         func(context.Context, *Target) []model.Finding { return nil },
	})
}

// partAInfo is a small constructor for engine.CheckInfo values.
func partAInfo(id, title string, sev model.Severity, services []string, desc string) (info engine.CheckInfo) {
	info.ID, info.Title, info.Severity, info.Services, info.Description = id, title, sev, services, desc
	return info
}

func runSMBSigning(ctx context.Context, t *Target) []model.Finding {
	c, err := smb.Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		t.Log.Debug("smb dial failed", "err", err)
		return nil
	}
	ni, err := c.Negotiate()
	c.Close()
	if err == nil {
		if ni.SigningRequired {
			return nil
		}
		ev := fmt.Sprintf("SMB2 NEGOTIATE response: dialect %s, SecurityMode=0x%04x (signing enabled=%v, required=false)",
			ni.DialectString(), ni.SecurityMode, ni.SigningEnabled)
		return []model.Finding{t.Finding(ev)}
	}
	if !errors.Is(err, smb.ErrSMB1Only) {
		t.Log.Debug("smb2 negotiate failed", "err", err)
		// Fall through to SMB1: some legacy stacks just reset SMB2 attempts.
	}
	c1, err := smb1Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		return nil
	}
	defer c1.Close()
	n1, err := c1.Negotiate()
	if err != nil || !n1.Accepted || n1.SigningRequired {
		return nil
	}
	ev := fmt.Sprintf("SMB1 NEGOTIATE response (SMB2 unsupported): SecurityMode=0x%02x (signing enabled=%v, required=false)", n1.SecurityMode, n1.SigningEnabled)
	return []model.Finding{t.Finding(ev)}
}

func runSMBv1(ctx context.Context, t *Target) []model.Finding {
	c, err := smb1Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	ni, err := c.Negotiate()
	if err != nil {
		t.Log.Debug("smb1 negotiate failed", "err", err)
		return nil
	}
	if !ni.Accepted {
		return nil
	}
	ev := fmt.Sprintf("Server accepted SMB1 dialect 'NT LM 0.12' (SecurityMode=0x%02x, capabilities=0x%08x [%s])",
		ni.SecurityMode, ni.Capabilities, smb1CapsString(ni.Capabilities))
	return []model.Finding{t.Finding(ev)}
}

func runSMBGuest(ctx context.Context, t *Target) []model.Finding {
	var out []model.Finding
	// 1) Guest account with empty password.
	out = append(out, runSMBSessionCheck(ctx, t, &ntlm.Credentials{User: "Guest"})...)
	if len(out) > 0 || ctx.Err() != nil {
		return out
	}
	// 2) Random unknown user: servers with "map to guest = bad user" (or
	// Windows with Guest enabled) map it to a guest session.
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	return runSMBSessionCheck(ctx, t, &ntlm.Credentials{User: "nety" + hex.EncodeToString(rnd)})
}

// smbSessionResult summarises what a null/guest session could do.
type smbSessionResult struct {
	sessionOK  bool
	guestFlag  bool
	ipcOK      bool
	shares     []rpcShare
	enumErr    error
	accessible []string
}

// runSMBSessionCheck opens a session (cred == nil: anonymous) and reports
// smb-null-session / smb-guest-access plus smb-anonymous-share-access.
func runSMBSessionCheck(ctx context.Context, t *Target, cred *ntlm.Credentials) []model.Finding {
	res, err := smbProbeSession(ctx, t, cred)
	if err != nil {
		t.Log.Debug("smb session probe", "err", err, "anonymous", cred == nil)
	}
	if res == nil || !res.sessionOK {
		return nil
	}
	var out []model.Finding
	what := "anonymous (null) session"
	if cred != nil {
		if !res.guestFlag && !strings.EqualFold(cred.User, "guest") {
			// An unknown random user must map to guest; a real session
			// without the guest flag would be very unusual: ignore.
			return nil
		}
		what = fmt.Sprintf("session as user %q with an empty password (server flagged it guest=%v)", cred.User, res.guestFlag)
	}
	var ev strings.Builder
	fmt.Fprintf(&ev, "SMB %s established on port %d", what, t.Service.Port)
	if res.ipcOK {
		ev.WriteString("; IPC$ tree connect succeeded")
	}
	if len(res.shares) > 0 {
		ev.WriteString("; shares enumerated via srvsvc NetShareEnumAll:\n")
		for _, s := range res.shares {
			fmt.Fprintf(&ev, "  %-20s %-16s %s\n", s.Name, s.TypeName(), s.Remark)
		}
	} else if res.enumErr != nil {
		fmt.Fprintf(&ev, "; share enumeration failed: %v", res.enumErr)
	}
	if cred == nil {
		// A bare anonymous session + IPC$ is the Windows default and not a
		// finding by itself: require enumeration or share access.
		if len(res.shares) > 0 || len(res.accessible) > 0 {
			out = append(out, t.Finding(ev.String()))
		}
	} else if res.ipcOK {
		out = append(out, smbFindingFor(t, "smb-guest-access", ev.String()))
	}
	if len(res.accessible) > 0 {
		e := fmt.Sprintf("Shares opened and listed using a %s: %s", what, strings.Join(res.accessible, ", "))
		out = append(out, smbFindingFor(t, "smb-anonymous-share-access", e))
	}
	return out
}

// smbFindingFor builds a finding for another registered check id.
func smbFindingFor(t *Target, id, evidence string) model.Finding {
	for _, c := range allChecks() {
		if c.Info.ID == id {
			tt := *t
			tt.check = c
			return tt.Finding(evidence)
		}
	}
	return t.Finding(evidence)
}

func smbProbeSession(ctx context.Context, t *Target, cred *ntlm.Credentials) (*smbSessionResult, error) {
	c, err := smb.Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Negotiate(); err != nil {
		return nil, err
	}
	si, err := c.Login(cred)
	if err != nil {
		return &smbSessionResult{}, err
	}
	res := &smbSessionResult{sessionOK: true, guestFlag: si.Guest}
	if si.Encrypt {
		return res, errors.New("server requires encryption for this session")
	}
	ipc, err := c.TreeConnect("IPC$")
	if err != nil {
		return res, err
	}
	res.ipcOK = true
	res.shares, res.enumErr = smbEnumShares(c, ipc, t.IP)
	_ = c.TreeDisconnect(ipc)
	// Try to open the root of each non-default disk share (read-only).
	tested := 0
	for _, s := range res.shares {
		if ctx.Err() != nil || tested >= 20 {
			break
		}
		if s.Type&0x0fffffff != 0 || smbDefaultShare(s.Name) || s.Name == "" {
			continue
		}
		tested++
		if smbCanListShare(c, s.Name) {
			res.accessible = append(res.accessible, s.Name)
		}
	}
	sort.Strings(res.accessible)
	return res, nil
}

// smbDefaultShare reports administrative/default shares that are not
// interesting for anonymous access (and normally denied anyway).
func smbDefaultShare(name string) bool {
	n := strings.ToUpper(name)
	switch n {
	case "IPC$", "PRINT$", "ADMIN$":
		return true
	}
	return len(n) == 2 && n[1] == '$' && n[0] >= 'A' && n[0] <= 'Z'
}

// smbCanListShare tree-connects to share and opens its root directory for
// listing (read-only access mask). Everything is closed afterwards.
func smbCanListShare(c *smb.Conn, share string) bool {
	tr, err := c.TreeConnect(share)
	if err != nil {
		return false
	}
	defer func() { _ = c.TreeDisconnect(tr) }()
	// SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, share all,
	// FILE_OPEN, FILE_DIRECTORY_FILE.
	fid, err := c.Create(tr, "", 0x00100081, 0x7, 1, 0x1)
	if err != nil {
		return false
	}
	_ = c.CloseFile(tr, fid)
	return true
}

// smbEnumShares runs srvsvc NetrShareEnum level 1 over the IPC$ tree.
func smbEnumShares(c *smb.Conn, ipc *smb.Tree, server string) ([]rpcShare, error) {
	fid, err := c.OpenPipe(ipc, "srvsvc")
	if err != nil {
		return nil, fmt.Errorf("open srvsvc: %w", err)
	}
	defer func() { _ = c.CloseFile(ipc, fid) }()
	resp, err := c.Transceive(ipc, fid, rpcBuildBind(rpcSrvsvcUUID, 3, 0, 1), 64<<10)
	if err != nil {
		return nil, fmt.Errorf("srvsvc bind: %w", err)
	}
	if err := rpcCheckBindAck(resp); err != nil {
		return nil, err
	}
	data, err := c.Transceive(ipc, fid, rpcBuildRequest(15, rpcNetShareEnumRequest(server), 2), rpcMaxStub)
	if err != nil {
		return nil, fmt.Errorf("srvsvc request: %w", err)
	}
	for i := 0; i < 256; i++ {
		stub, done, err := rpcAssembleResponse(data)
		if err != nil {
			return nil, err
		}
		if done {
			return rpcParseNetShareEnumResponse(stub)
		}
		more, _, err := c.Read(ipc, fid, rpcMaxFrag)
		if err != nil || len(more) == 0 {
			return nil, fmt.Errorf("srvsvc: incomplete response: %v", err)
		}
		data = append(data, more...)
		if len(data) > rpcMaxStub {
			return nil, errors.New("srvsvc: response too large")
		}
	}
	return nil, errors.New("srvsvc: too many fragments")
}
