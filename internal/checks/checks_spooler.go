package checks

import (
	"context"
	"fmt"

	"github.com/GoToolSharing/nety/internal/identity/smb"
	"github.com/GoToolSharing/nety/internal/model"
)

// MS-RPRN, the Print System Remote Protocol:
// 12345678-1234-abcd-ef00-0123456789ab v1.0 over the \pipe\spoolss named pipe.
var rpcSpoolssUUID = rpcUUID("12345678-1234-abcd-ef00-0123456789ab")

func init() {
	register(&Check{
		Info: checkInfo("ms-rprn-spooler", "Print spooler RPC interface reachable (coercion vector)", model.SevMedium,
			[]string{"microsoft-ds", "netbios-ssn"},
			"The Print System Remote Protocol (MS-RPRN) answers on this host's \\pipe\\spoolss named pipe. The interface has a call that makes the spooler connect back to a caller-supplied server and authenticate as the machine account; that is the PrinterBug coercion, and it is the usual way an attacker produces the machine authentication they then relay to LDAP or to AD CS web enrolment. On a domain controller it is worse, because the account coerced is the domain controller's. The spooler is also the interface behind the PrintNightmare family of privilege escalation bugs."),
		Remediation: "Stop and disable the Print Spooler service on every server that does not print, domain controllers first. Where it must run, restrict inbound RPC to the print servers and apply the RpcAuthnLevelPrivacyEnabled and PointAndPrint restrictions. Fixing the relay targets (SMB signing, LDAP signing and channel binding, EPA on /certsrv) removes the value of the coercion.",
		References: []string{
			"https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1",
			"https://attack.mitre.org/techniques/T1187/",
		},
		Applies: smbApplies,
		Run:     runMSRPRNSpooler,
	})
}

// runMSRPRNSpooler establishes an anonymous SMB session, opens the spooler
// pipe and binds to the interface. It stops there on purpose: proving the
// interface is listening needs a BIND_ACK and nothing more. The calls that
// make the spooler authenticate somewhere (RpcRemoteFindFirstPrinterChange-
// NotificationEx and friends) are never sent, so no authentication is ever
// coerced out of the host.
func runMSRPRNSpooler(ctx context.Context, t *Target) []model.Finding {
	c, err := smb.Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Negotiate(); err != nil {
		return nil
	}
	if _, err := c.Login(nil); err != nil {
		t.Log.Debug("spoolss: anonymous session refused", "err", err)
		return nil
	}
	ipc, err := c.TreeConnect("IPC$")
	if err != nil {
		t.Log.Debug("spoolss: IPC$ refused", "err", err)
		return nil
	}
	defer func() { _ = c.TreeDisconnect(ipc) }()
	fid, err := c.OpenPipe(ipc, "spoolss")
	if err != nil {
		t.Log.Debug("spoolss: pipe not opened", "err", err)
		return nil
	}
	defer func() { _ = c.CloseFile(ipc, fid) }()
	resp, err := c.Transceive(ipc, fid, rpcBuildBind(rpcSpoolssUUID, 1, 0, 1), 64<<10)
	if err != nil {
		t.Log.Debug("spoolss: bind failed", "err", err)
		return nil
	}
	if err := rpcCheckBindAck(resp); err != nil {
		t.Log.Debug("spoolss: bind rejected", "err", err)
		return nil
	}
	ev := fmt.Sprintf("Anonymous SMB session on %d/tcp opened \\pipe\\spoolss and the DCE/RPC bind to MS-RPRN (12345678-1234-abcd-ef00-0123456789ab v1.0) was acknowledged.\n"+
		"The check stopped at the bind: no printer call was made, so no authentication was coerced from this host.", t.Service.Port)
	return []model.Finding{t.Finding(ev)}
}
