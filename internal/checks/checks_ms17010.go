package checks

import (
	"context"
	"fmt"

	"github.com/vaadata/nety/internal/identity/smb"
	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: partAInfo("ms17-010", "MS17-010 (EternalBlue) remote code execution", model.SevCritical,
			[]string{"microsoft-ds", "netbios-ssn"},
			"The SMBv1 server is missing the MS17-010 security update. Unauthenticated attackers can execute arbitrary code as SYSTEM (EternalBlue / EternalRomance, used by WannaCry and NotPetya). Detection is non-intrusive: a PeekNamedPipe transaction on FID 0 over an anonymous IPC$ session returns STATUS_INSUFF_SERVER_RESOURCES on unpatched systems (same logic as nmap smb-vuln-ms17-010)."),
		Remediation: "Apply the MS17-010 security update (KB4012598 and later cumulative updates) immediately and disable SMBv1.",
		References: []string{
			"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
			"https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
			"https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html",
		},
		Applies: smbApplies,
		Run:     runMS17010,
	})
}

// ms17Verdict interprets the PeekNamedPipe status.
func ms17Verdict(status uint32) (vulnerable bool, known bool) {
	switch status {
	case smb.StatusInsuffServerResources:
		return true, true
	case smb.StatusAccessDenied, smb.StatusInvalidHandle:
		return false, true
	}
	return false, false
}

func runMS17010(ctx context.Context, t *Target) []model.Finding {
	c, err := smb1Dial(ctx, t.IP, t.Service.Port, t.Timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	ni, err := c.Negotiate()
	if err != nil || !ni.Accepted {
		return nil // no SMB1: not exploitable via this vector
	}
	if err := c.SessionSetupAnon(); err != nil {
		t.Log.Debug("ms17-010: anonymous session refused", "err", err)
		return nil
	}
	if err := c.TreeConnect("IPC$"); err != nil {
		t.Log.Debug("ms17-010: IPC$ refused", "err", err)
		return nil
	}
	st, err := c.PeekNamedPipe()
	if err != nil {
		t.Log.Debug("ms17-010: transaction failed", "err", err)
		return nil
	}
	vuln, known := ms17Verdict(st)
	t.Log.Debug("ms17-010 verdict", "status", smb.StatusName(st), "vulnerable", vuln, "known", known)
	if !vuln {
		return nil
	}
	return []model.Finding{t.Finding(fmt.Sprintf(
		"SMB1 TRANS PeekNamedPipe on FID 0 (anonymous IPC$ session) returned %s (0x%08x): the host is missing MS17-010.",
		smb.StatusName(st), st))}
}
