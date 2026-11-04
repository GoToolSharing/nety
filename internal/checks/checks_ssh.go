package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vaadata/nety/internal/model"
)

func init() {
	register(&Check{
		Info: partAInfo("ssh-weak-algorithms", "SSH server supports weak algorithms", model.SevLow,
			[]string{"ssh"},
			"The SSH server offers deprecated key exchange, encryption or MAC algorithms (SHA-1 based or small Diffie-Hellman groups, CBC mode / RC4 / 3DES ciphers, MD5 or truncated MACs) that weaken the confidentiality and integrity of sessions."),
		Remediation: "Restrict KexAlgorithms, Ciphers and MACs in sshd_config to modern algorithms (curve25519-sha256, sntrup761x25519-sha512, chacha20-poly1305, aes*-gcm, aes*-ctr, hmac-sha2-*-etm) and upgrade the SSH server.",
		References:  []string{"https://www.ssh-audit.com/hardening_guides.html", "https://datatracker.ietf.org/doc/html/rfc9142"},
		Applies:     sshApplies,
		Run:         runSSHWeakAlgos,
	})
	register(&Check{
		Info: partAInfo("ssh-protocol-v1", "SSH protocol version 1 supported", model.SevMedium,
			[]string{"ssh"},
			"The SSH server supports protocol version 1, which has fundamental cryptographic flaws (CRC-32 integrity, session hijacking and credential interception attacks)."),
		Remediation: "Disable SSH protocol 1 (Protocol 2 in sshd_config) or upgrade the SSH server.",
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2001-0361"},
		Applies:     sshApplies,
		Run:         runSSHv1,
	})
	register(&Check{
		Info: partAInfo("ssh-password-auth", "SSH password authentication enabled", model.SevInfo,
			[]string{"ssh"},
			"The SSH server accepts password (or keyboard-interactive) authentication, exposing accounts to password guessing; public key authentication is preferable for administrative access."),
		Remediation: "Prefer public-key authentication (PasswordAuthentication no, KbdInteractiveAuthentication no) and enforce rate limiting / fail2ban where passwords are required.",
		References:  []string{"https://attack.mitre.org/techniques/T1110/"},
		Applies:     func(t *Target) bool { return sshApplies(t) && t.Service.SSH != nil && len(t.Service.SSH.AuthMeth) > 0 },
		Run:         runSSHPasswordAuth,
	})
}

func sshApplies(t *Target) bool {
	s := t.Service
	return s.Protocol == model.TCP && (strings.EqualFold(s.Name, "ssh") || s.SSH != nil || strings.HasPrefix(s.Banner, "SSH-"))
}

// sshWeak classifies weak algorithm names; returns a reason or "".
func sshWeakKex(a string) string {
	switch a {
	case "diffie-hellman-group1-sha1":
		return "1024-bit DH group with SHA-1"
	case "diffie-hellman-group14-sha1":
		return "SHA-1 based"
	case "diffie-hellman-group-exchange-sha1":
		return "SHA-1 based"
	case "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==", "rsa1024-sha1":
		return "weak (1024-bit / SHA-1)"
	}
	if strings.HasPrefix(a, "gss-group1-sha1") || strings.HasPrefix(a, "gss-gex-sha1") {
		return "SHA-1 based"
	}
	return ""
}

func sshWeakCipher(a string) string {
	switch {
	case strings.HasPrefix(a, "arcfour"):
		return "RC4"
	case a == "3des-cbc" || a == "3des-ctr":
		return "3DES (64-bit block, SWEET32)"
	case strings.HasPrefix(a, "blowfish") || strings.HasPrefix(a, "cast128") || strings.HasPrefix(a, "idea"):
		return "64-bit block cipher"
	case a == "none":
		return "no encryption"
	case a == "des-cbc" || a == "des-cbc@ssh.com":
		return "DES"
	case strings.HasSuffix(a, "-cbc") || strings.HasSuffix(a, "-cbc@lysator.liu.se") || strings.HasSuffix(a, "-cbc@openssh.org"):
		return "CBC mode (plaintext recovery, CVE-2008-5161)"
	}
	return ""
}

func sshWeakMAC(a string) string {
	switch {
	case a == "none":
		return "no integrity"
	case strings.HasPrefix(a, "hmac-md5"):
		return "MD5 based"
	case strings.HasPrefix(a, "hmac-sha1-96"):
		return "truncated SHA-1"
	case strings.HasPrefix(a, "umac-64"):
		return "64-bit tag"
	case strings.HasPrefix(a, "hmac-ripemd160"):
		return "deprecated"
	}
	return ""
}

func sshCollectWeak(label string, algos []string, fn func(string) string) []string {
	var out []string
	for _, a := range algos {
		if r := fn(strings.ToLower(strings.TrimSpace(a))); r != "" {
			out = append(out, fmt.Sprintf("%s %s (%s)", label, a, r))
		}
	}
	return out
}

func runSSHWeakAlgos(_ context.Context, t *Target) []model.Finding {
	si := t.Service.SSH
	if si == nil {
		return nil
	}
	var weak []string
	weak = append(weak, sshCollectWeak("kex", si.KexAlgos, sshWeakKex)...)
	weak = append(weak, sshCollectWeak("cipher", si.Ciphers, sshWeakCipher)...)
	weak = append(weak, sshCollectWeak("mac", si.MACs, sshWeakMAC)...)
	if len(weak) == 0 {
		return nil
	}
	ev := "Weak algorithms offered in SSH_MSG_KEXINIT"
	if si.Banner != "" {
		ev += " by " + si.Banner
	}
	return []model.Finding{t.Finding(ev + ":\n  " + strings.Join(weak, "\n  "))}
}

func runSSHv1(_ context.Context, t *Target) []model.Finding {
	b := t.Service.Banner
	if t.Service.SSH != nil && t.Service.SSH.Banner != "" {
		b = t.Service.SSH.Banner
	}
	b = strings.TrimSpace(b)
	if !strings.HasPrefix(b, "SSH-1.") {
		return nil
	}
	// "SSH-1.99" means v1 and v2 supported; "SSH-1.5" / "SSH-1.3" v1 only.
	return []model.Finding{t.Finding("Server identification string: " + printable([]byte(b), 200))}
}

func runSSHPasswordAuth(_ context.Context, t *Target) []model.Finding {
	si := t.Service.SSH
	if si == nil {
		return nil
	}
	for _, m := range si.AuthMeth {
		if m == "password" || m == "keyboard-interactive" {
			return []model.Finding{t.Finding("Authentication methods advertised: " + strings.Join(si.AuthMeth, ", "))}
		}
	}
	return nil
}
