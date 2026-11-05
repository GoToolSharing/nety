package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("ldap-signing-not-required", "LDAP signing not required by the directory", model.SevHigh,
			[]string{"ldap", "globalcatldap"},
			"The directory accepts a cleartext simple bind on the unencrypted LDAP port, which means it does not require signing (LDAPServerIntegrity is not set to 2). Together with the SMB side (see smb-signing-not-required) this is what makes an NTLM relay possible: an attacker who coerces or captures an authentication relays it to the directory, and because nothing binds the authentication to the channel the directory accepts it. Relayed to a domain controller's LDAP service, that is enough to add a computer account, write msDS-KeyCredentialLink on a user, or grant DCSync rights. Either side of the pair on its own is a weakness; both together are a path to domain compromise."),
		Remediation: "Set 'Domain controller: LDAP server signing requirements' to 'Require signing' (LDAPServerIntegrity=2) and 'Domain controller: LDAP server channel binding token requirements' to 'Always' by GPO, after confirming with the LDAP interface events (2886/2887/2889) that no application still binds without signing. Fix smb-signing-not-required at the same time: relay protection needs both.",
		References: []string{
			"https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a",
			"https://attack.mitre.org/techniques/T1557/001/",
		},
		Applies: ldapSigningApplies,
		Run:     runLDAPSigning,
	})
}

// ldapSigningApplies selects the cleartext LDAP port only. On LDAPS the TLS layer already
// provides the integrity the bind would otherwise need, so the same probe there would say
// nothing about the signing policy.
func ldapSigningApplies(t *Target) bool {
	s := t.Service
	if s.Protocol != model.TCP || ldapUseTLS(s) {
		return false
	}
	if strings.HasPrefix(strings.ToLower(s.Name), "ldap") || strings.HasPrefix(strings.ToLower(s.Name), "globalcat") {
		return true
	}
	return svcIs(s, model.TCP, nil, 389, 3268)
}

// LDAP result codes used below (RFC 4511 4.1.9).
const (
	ldapResultSuccess             = 0
	ldapResultStrongerAuthReq     = 8
	ldapResultInvalidCredentials  = 49
	ldapResultUnwillingToPerform  = 53
	ldapResultConfidentialityReq  = 13
	ldapResultInappropriateAuthen = 48
)

// ldapSimpleBind builds a simple bind with a name and a password.
func ldapSimpleBind(id int, name, password string) []byte {
	return ldapMessage(id, ntlm.DER(0x60, ldapInt(0x02, 3), ldapStr(0x04, name), ldapStr(0x80, password)))
}

// runLDAPSigning asks the directory one question: would it accept a cleartext simple bind
// at all?
//
// The bind is sent for an account name that is generated at random and therefore cannot
// exist, with a random password, and NETY only reads the refusal code. That is not
// credential guessing: the bind is meant to fail, and a name that does not exist cannot
// be locked out. What distinguishes the two configurations is *how* it fails. A directory
// that requires signing refuses the bind before it ever looks at the credential
// (unwillingToPerform with "data 0" / the 00002028 LdapErr, or strongerAuthRequired); one
// that does not require signing looks the account up and answers invalidCredentials.
func runLDAPSigning(ctx context.Context, t *Target) []model.Finding {
	conn, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer conn.Close()
	l := &ldapConn{c: conn, timeout: t.Timeout}
	defer func() { _ = l.send(ldapUnbind(9)) }()

	// A rootDSE read first, so the check only reports against something that really is an
	// LDAP server.
	if err := l.send(ldapBindRequest(1)); err != nil {
		return nil
	}
	anon, err := l.recv()
	if err != nil || anon.Op != 0x61 {
		return nil
	}
	root, _, err := l.search(2, "", 0, 1, []string{"supportedLDAPVersion", "defaultNamingContext", "dnsHostName", "supportedSASLMechanisms"})
	if err != nil || len(root) == 0 {
		t.Log.Debug("ldap rootDSE read failed", "err", err)
		return nil
	}

	// Signing requirements as described here are an Active Directory setting, and the
	// relay they prevent targets AD. Reporting this against an OpenLDAP server would put
	// a remediation in the report that does not exist on that product, so the check stops
	// unless the rootDSE is AD's.
	if !ldapLooksLikeAD(root[0].Attrs) {
		return nil
	}

	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	user := "nety-probe-" + hex.EncodeToString(rnd)
	pass := hex.EncodeToString(rnd) + "-no-such-secret"
	if err := l.send(ldapSimpleBind(3, user, pass)); err != nil {
		return nil
	}
	res, err := l.recv()
	if err != nil || res.Op != 0x61 {
		t.Log.Debug("ldap simple bind answer", "err", err)
		return nil
	}

	switch res.Result {
	case ldapResultUnwillingToPerform, ldapResultStrongerAuthReq, ldapResultConfidentialityReq, ldapResultInappropriateAuthen:
		// The directory refused the bind on the grounds of the channel, which is exactly
		// the configuration that is wanted.
		t.Log.Debug("ldap signing enforced", "result", res.Result, "diag", res.Diag)
		return nil
	case ldapResultSuccess:
		// A non-existent account must never authenticate; something answered that is not
		// the directory this check reasons about.
		return nil
	case ldapResultInvalidCredentials:
	default:
		return nil
	}

	ra := root[0].Attrs
	var ev strings.Builder
	ev.WriteString("Simple bind over cleartext LDAP was processed rather than refused: the directory does not require signing.\n")
	fmt.Fprintf(&ev, "  bind name   %s (generated at random, cannot exist)\n", user)
	fmt.Fprintf(&ev, "  result      %d invalidCredentials\n", res.Result)
	if res.Diag != "" {
		fmt.Fprintf(&ev, "  diagnostic  %s\n", truncate(res.Diag, 300))
	}
	ev.WriteString("A directory that requires signing answers unwillingToPerform (00002028) or strongerAuthRequired instead, without looking the account up.\n")
	if h := ra["dnshostname"]; len(h) > 0 {
		fmt.Fprintf(&ev, "  rootDSE dnsHostName %s\n", h[0])
	}
	if d := ra["defaultnamingcontext"]; len(d) > 0 {
		fmt.Fprintf(&ev, "  defaultNamingContext %s\n", d[0])
	}
	ev.WriteString(ldapChannelBindingNote(t))
	if t.HasPort(445, model.TCP) {
		ev.WriteString("\nSMB is open on this host as well: check smb-signing-not-required on the same address, the relay needs only one of the two to be unprotected.")
	}
	return []model.Finding{t.Finding(strings.TrimRight(ev.String(), "\n"))}
}

// ldapLooksLikeAD reports whether the rootDSE is Active Directory's.
func ldapLooksLikeAD(attrs map[string][]string) bool {
	if len(attrs["defaultnamingcontext"]) > 0 {
		return true
	}
	for _, m := range attrs["supportedsaslmechanisms"] {
		if strings.EqualFold(m, "GSS-SPNEGO") {
			return true
		}
	}
	return false
}

// ldapChannelBindingNote states what is known about channel binding and, just as
// importantly, what is not. Confirming LdapEnforceChannelBinding needs a SASL bind with a
// credential that is accepted, because the server only looks at the channel binding token
// after the credential validates. NETY has no credential to bind with, so it reports what
// it saw and says plainly that the rest has to be read from the configuration.
func ldapChannelBindingNote(t *Target) string {
	ldaps := t.ServiceOn(636, model.TCP)
	if ldaps == nil {
		ldaps = t.ServiceOn(3269, model.TCP)
	}
	if ldaps == nil {
		return "\nNo LDAPS port (636/3269) is open on this host, so clients have no encrypted alternative to the unsigned channel."
	}
	return fmt.Sprintf("\nLDAPS is available on %d/tcp. Whether channel binding is enforced there was not determined: the server validates the channel binding token only after a credential is accepted, and this check sends none. Verify LdapEnforceChannelBinding on the domain controller, and the 3039/3040/3041 LDAP interface events.", ldaps.Port)
}
