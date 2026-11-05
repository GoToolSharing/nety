package fingerprint

import (
	"regexp"
	"strings"
)

// bannerRule recognises a service from the bytes it volunteers on connect (or from the
// answer to the NULL probe). These rules are the safety net used when nmap's
// service-probes file is not installed: they cover the protocols an internal network is
// actually made of, nothing more.
//
// re is matched against the printable rendering of the banner (see printable), so \r, \n
// and \xNN escapes are literal two/four-character sequences.
type bannerRule struct {
	re      *regexp.Regexp
	name    string
	product string // may contain $1..$9 referring to re's capture groups
	version string
	extra   string
	ostype  string
	cpe     string // "$v" is replaced by the resolved version
}

var bannerRules = []bannerRule{
	// --- mail -------------------------------------------------------------
	{re: rx(`^220[- ].*\bESMTP\b.*?Postfix(?: \(([^)]+)\))?`), name: "smtp", product: "Postfix smtpd", version: "$1", cpe: "cpe:/a:postfix:postfix"},
	{re: rx(`^220[- ].*\bExim\b ([\d.]+)`), name: "smtp", product: "Exim smtpd", version: "$1", cpe: "cpe:/a:exim:exim:$v"},
	{re: rx(`^220[- ].*Sendmail\b[^;]*?([\d.]+(?:/[\d.]+)?)`), name: "smtp", product: "Sendmail", version: "$1", cpe: "cpe:/a:sendmail:sendmail:$v"},
	{re: rx(`^220[- ].*Microsoft ESMTP MAIL Service.*?Version: ?([\d.]+)`), name: "smtp", product: "Microsoft Exchange smtpd", version: "$1", ostype: "Windows", cpe: "cpe:/a:microsoft:exchange_server"},
	{re: rx(`^220[- ].*\bQmail\b|^220[- ].*qmail`), name: "smtp", product: "qmail smtpd", cpe: "cpe:/a:qmail:qmail"},
	{re: rx(`^220[- ].*\bZimbra\b`), name: "smtp", product: "Zimbra smtpd", cpe: "cpe:/a:zimbra:zimbra_collaboration_suite"},
	{re: rx(`^220[- ].*\b(?:SMTP|ESMTP)\b`), name: "smtp"},
	{re: rx(`^\+OK .*\bDovecot\b`), name: "pop3", product: "Dovecot pop3d", cpe: "cpe:/a:dovecot:dovecot"},
	{re: rx(`^\+OK\b`), name: "pop3"},
	{re: rx(`^\* OK .*\bDovecot\b(?: ready)?`), name: "imap", product: "Dovecot imapd", cpe: "cpe:/a:dovecot:dovecot"},
	{re: rx(`^\* OK .*Microsoft Exchange`), name: "imap", product: "Microsoft Exchange imapd", ostype: "Windows"},
	{re: rx(`^\* (?:OK|PREAUTH)\b`), name: "imap"},
	{re: rx(`^200[- ].*\bNNTP\b|^200 .*\bINN\b`), name: "nntp"},

	// --- file transfer / shells -------------------------------------------
	{re: rx(`^220[- ].*\bvsFTPd ([\w.]+)`), name: "ftp", product: "vsftpd", version: "$1", cpe: "cpe:/a:vsftpd_project:vsftpd:$v"},
	{re: rx(`^220[- ].*\bProFTPD ([\w.]+)`), name: "ftp", product: "ProFTPD", version: "$1", cpe: "cpe:/a:proftpd:proftpd:$v"},
	{re: rx(`^220[- ].*\bPure-FTPd\b`), name: "ftp", product: "Pure-FTPd", cpe: "cpe:/a:pureftpd:pure-ftpd"},
	{re: rx(`^220[- ].*\bFileZilla Server\b[^\d]*([\d.]+)?`), name: "ftp", product: "FileZilla ftpd", version: "$1", ostype: "Windows"},
	{re: rx(`^220[- ].*Microsoft FTP Service`), name: "ftp", product: "Microsoft ftpd", ostype: "Windows", cpe: "cpe:/a:microsoft:internet_information_services"},
	{re: rx(`^220[- ].*\bServ-U\b.*?([\d.]+)?`), name: "ftp", product: "Serv-U ftpd", version: "$1", ostype: "Windows"},
	{re: rx(`^220[- ]`), name: "ftp"},
	{re: rx(`^@RSYNCD: ([\d.]+)`), name: "rsync", product: "rsyncd", version: "$1", cpe: "cpe:/a:samba:rsync:$v"},

	// --- databases / caches ------------------------------------------------
	{re: rx(`^.\x00\x00\x00\\n(\d+\.[\w.\-]+)`), name: "mysql", product: "MySQL", version: "$1", cpe: "cpe:/a:mysql:mysql:$v"},
	{re: rx(`\\n(\d+\.\d+\.\d+[\w.\-]*-MariaDB[\w.\-]*)`), name: "mysql", product: "MariaDB", version: "$1", cpe: "cpe:/a:mariadb:mariadb:$v"},
	{re: rx(`\\n(\d+\.\d+\.\d+[\w.\-]*)\\x00`), name: "mysql", product: "MySQL", version: "$1", cpe: "cpe:/a:mysql:mysql:$v"},
	{re: rx(`^E\\x00\\x00\\x00.*FATAL`), name: "postgresql", product: "PostgreSQL", cpe: "cpe:/a:postgresql:postgresql"},
	{re: rx(`^-NOAUTH|^-ERR operation not permitted|^\+PONG`), name: "redis", product: "Redis key-value store", extra: "authentication required"},
	{re: rx(`^-ERR unknown command|^\+OK\\r\\n$`), name: "redis", product: "Redis key-value store"},
	{re: rx(`^STAT pid \d+|^VERSION ([\d.]+)`), name: "memcached", product: "Memcached", version: "$1", cpe: "cpe:/a:memcached:memcached:$v"},
	{re: rx(`^HTTP/1\.[01] \d\d\d .*\\r\\nContent-Type: application/json.*"cluster_name"`), name: "elasticsearch", product: "Elasticsearch"},
	{re: rx(`^\\x00\\x00\\x00.\\xff(?:SMBr|SMB)`), name: "netbios-ssn", product: "Samba smbd", ostype: "Windows"},
	{re: rx(`^\\xfeSMB`), name: "microsoft-ds", product: "SMBv2", ostype: "Windows"},

	// --- remote access / display ------------------------------------------
	{re: rx(`^RFB (\d{3})\.(\d{3})`), name: "vnc", product: "VNC", extra: "protocol $1.$2"},
	{re: rx(`^\\x03\\x00\\x00`), name: "ms-wbt-server", product: "Microsoft Terminal Services", ostype: "Windows", cpe: "cpe:/o:microsoft:windows"},
	{re: rx(`^\\xff\\xfd|^\\xff\\xfb|^\\xff\\xfe`), name: "telnet"},
	{re: rx(`Telnet|telnetd|login:\s*$`), name: "telnet"},

	// --- directory / auth ---------------------------------------------------
	{re: rx(`^0.\\x02\\x01\\x01a`), name: "ldap", product: "LDAP server"},

	// --- infrastructure ----------------------------------------------------
	{re: rx(`^\\x00\\x00\\x00.\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00`), name: "msrpc", ostype: "Windows"},
	{re: rx(`^AMQP\\x00`), name: "amqp", product: "RabbitMQ"},
	{re: rx(`^\\x00\\x00\\x00.\\x00\\x00\\x00\\x00`), name: "zookeeper"},
	{re: rx(`^\\x16\\x03`), name: "ssl", extra: "TLS record on a plaintext read"},
	{re: rx(`^\(\x00|^\\x00(?:[\\\w]{0,8})TNSLSNR`), name: "oracle-tns", product: "Oracle TNS Listener", cpe: "cpe:/a:oracle:database_server"},
	{re: rx(`^\\x04\\x01\\x00`), name: "ms-sql-s", product: "Microsoft SQL Server", ostype: "Windows"},
	{re: rx(`^:\S+ NOTICE|^:\S+ \d\d\d `), name: "irc"},
	{re: rx(`^SIP/2\.0 \d\d\d`), name: "sip"},
	{re: rx(`^RTSP/1\.0 \d\d\d`), name: "rtsp"},
	{re: rx(`^JDWP-Handshake`), name: "jdwp", product: "Java Debug Wire Protocol", extra: "remote code execution by design"},
	{re: rx(`^\\x4a\\x52\\x4d\\x49|^\\x00\\x00\\x00\\x76\\xac\\xed`), name: "java-rmi", product: "Java RMI"},
	{re: rx(`^ActiveMQ|^\\x00\\x00\\x00.\\x01ActiveMQ`), name: "activemq", product: "Apache ActiveMQ"},
	{re: rx(`^HTTP/1\.[01] \d\d\d`), name: "http"},
	{re: rx(`^\\x15\\x03`), name: "ssl", extra: "TLS alert"},
	{re: rx(`^\* ?OK|^OK\\r\\n`), name: "unknown"},
	{re: rx(`^#INFO|^PRINTER STATUS|^@PJL`), name: "printer", product: "PJL print service"},
	{re: rx(`^GDB|^\+\$`), name: "gdbserver"},
	{re: rx(`^SSH-`), name: "ssh"},
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + s) }

// bannerMatch identifies a service from a printable banner. ok is false when nothing
// recognisable was found.
func bannerMatch(banner string) (r bannerRule, version string, ok bool) {
	if banner == "" {
		return bannerRule{}, "", false
	}
	for _, rule := range bannerRules {
		m := rule.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		out := rule
		out.product = expandGroups(rule.product, m)
		out.extra = expandGroups(rule.extra, m)
		version = expandGroups(rule.version, m)
		out.cpe = strings.ReplaceAll(rule.cpe, "$v", version)
		if strings.HasSuffix(out.cpe, ":") {
			out.cpe = strings.TrimSuffix(out.cpe, ":")
		}
		return out, version, true
	}
	return bannerRule{}, "", false
}

// expandGroups substitutes $1..$9 with capture groups; "$$" is a literal $.
func expandGroups(tpl string, m []string) string {
	if tpl == "" || !strings.Contains(tpl, "$") {
		return tpl
	}
	var b strings.Builder
	for i := 0; i < len(tpl); i++ {
		if tpl[i] != '$' || i+1 >= len(tpl) {
			b.WriteByte(tpl[i])
			continue
		}
		c := tpl[i+1]
		switch {
		case c == '$':
			b.WriteByte('$')
			i++
		case c >= '1' && c <= '9':
			if n := int(c - '0'); n < len(m) {
				b.WriteString(m[n])
			}
			i++
		default:
			b.WriteByte('$')
		}
	}
	return strings.TrimSpace(b.String())
}

// looksHTTP reports whether a volunteered banner is an HTTP response, which happens with
// servers that answer before reading the request line.
func looksHTTP(b []byte) bool {
	return len(b) >= 5 && strings.HasPrefix(strings.ToUpper(string(b[:5])), "HTTP/")
}
