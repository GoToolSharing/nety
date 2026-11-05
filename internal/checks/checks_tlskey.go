package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("tls-weak-key", "TLS certificate uses a weak key or signature", model.SevMedium,
			[]string{"https", "ssl", "tls"},
			"The certificate presented by the service is signed with a broken hash algorithm (MD5 or SHA-1) or carries a key below the accepted strength (RSA/DSA under 2048 bits, elliptic curve under 224 bits). Chosen-prefix collisions against SHA-1 are practical, and short RSA keys are within reach of a well-funded attacker, so the certificate no longer proves the server's identity."),
		Remediation: "Reissue the certificate with at least a 2048-bit RSA key (3072 preferred) or a P-256 key, signed with SHA-256 or better. Retire DSA entirely and make the internal PKI refuse SHA-1 signatures.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/326.html",
			"https://shattered.io/",
			"https://nvd.nist.gov/vuln/detail/CVE-2005-4900",
		},
		Applies: func(t *Target) bool { return t.Service.TLS != nil },
		Run:     runTLSWeakKey,
	})
}

// minKeyBits is the smallest accepted key size per algorithm family.
var minKeyBits = map[string]int{
	"rsa":     2048,
	"dsa":     2048,
	"ecdsa":   224,
	"ed25519": 0, // fixed size, always acceptable
	"ed448":   0,
}

// weakSigAlgos are signature algorithms whose hash is broken for the purpose of
// certificate forgery.
var weakSigAlgos = []string{"md2", "md5", "sha1", "sha-1"}

func runTLSWeakKey(_ context.Context, t *Target) []model.Finding {
	ti := t.Service.TLS
	if ti == nil {
		return nil
	}
	var problems []string

	algo := normalizeKeyAlgo(ti.KeyAlgo)
	if min, ok := minKeyBits[algo]; ok && min > 0 && ti.KeyBits > 0 && ti.KeyBits < min {
		problems = append(problems, fmt.Sprintf("%s key of %d bits (minimum %d)",
			strings.ToUpper(algo), ti.KeyBits, min))
	}
	if algo == "dsa" {
		problems = append(problems, "DSA key: effectively obsolete, unsupported by modern clients")
	}
	if sig := strings.ToLower(strings.ReplaceAll(ti.SigAlgo, " ", "")); sig != "" {
		for _, w := range weakSigAlgos {
			if strings.Contains(sig, w) {
				// A self-signed root signs itself: the signature is not a trust decision
				// there, but a leaf certificate's is.
				problems = append(problems, fmt.Sprintf("signature algorithm %s", ti.SigAlgo))
				break
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	ev := fmt.Sprintf("Certificate CN=%q issued by %q (SHA256 %s):\n  %s",
		ti.SubjectCN, ti.Issuer, ti.SHA256, strings.Join(problems, "\n  "))
	f := t.Finding(ev)
	// An RSA key under 1024 bits is factorable today, not merely weak.
	if algo == "rsa" && ti.KeyBits > 0 && ti.KeyBits < 1024 {
		f.Severity = model.SevHigh
	}
	return []model.Finding{f}
}

// normalizeKeyAlgo maps the many spellings a fingerprinter may produce onto a canonical
// algorithm family.
func normalizeKeyAlgo(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "":
		return ""
	case strings.Contains(s, "ed25519"):
		return "ed25519"
	case strings.Contains(s, "ed448"):
		return "ed448"
	case strings.Contains(s, "ecdsa"), strings.Contains(s, "ec"), strings.Contains(s, "prime256"):
		return "ecdsa"
	case strings.Contains(s, "rsa"):
		return "rsa"
	case strings.Contains(s, "dsa"):
		return "dsa"
	}
	return s
}
