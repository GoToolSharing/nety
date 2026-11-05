package main

import (
	"github.com/GoToolSharing/nety/internal/checks"
	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// The invented estate. Four VLANs: offices, servers, telephony, management.

func demoHosts() []demoHost {
	var out []demoHost

	// ---- VLAN 10, offices ------------------------------------------------
	workstations := []struct {
		last int
		name string
		os   string
	}{
		{21, "PC-COMPTA-01", "Windows 11 23H2"},
		{22, "PC-COMPTA-02", "Windows 11 23H2"},
		{24, "PC-RH-01", "Windows 11 23H2"},
		{25, "PC-RH-02", "Windows 10 22H2"},
		{31, "PC-DIR-01", "Windows 11 23H2"},
		{33, "PC-COM-01", "Windows 10 22H2"},
		{34, "PC-COM-02", "Windows 10 22H2"},
		{41, "PC-DEV-01", "Ubuntu 24.04"},
		{42, "PC-DEV-02", "Ubuntu 24.04"},
		{47, "PC-SUPPORT-01", "Windows 10 22H2"},
	}
	for i, w := range workstations {
		h := demoHost{
			net: 0, last: w.last, hostname: w.name, os: w.os,
			mac: macFor("00:1a:2b", i), vendor: "Dell Inc.", kind: model.AssetWorkstation,
		}
		if w.os == "Ubuntu 24.04" {
			h.vendor = "LENOVO"
			h.services = []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "9.6p1",
					extra: "Ubuntu-3ubuntu13", banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", sshAlgos: true},
			}
			h.findings = []string{"ssh-weak-algorithms"}
			continue1 := h
			out = append(out, continue1)
			continue
		}
		h.services = []demoService{
			{port: 135, proto: model.TCP, name: "msrpc", product: "Microsoft Windows RPC"},
			{port: 139, proto: model.TCP, name: "netbios-ssn", product: "Microsoft Windows netbios-ssn"},
			{port: 445, proto: model.TCP, name: "microsoft-ds", product: "Windows SMB", version: "3.1.1"},
			{port: 5040, proto: model.TCP, name: "unknown"},
			{port: 137, proto: model.UDP, name: "netbios-ns", product: "Microsoft Windows netbios-ns"},
		}
		if i%3 == 0 {
			h.services = append(h.services, demoService{
				port: 3389, proto: model.TCP, name: "ms-wbt-server", product: "Microsoft Terminal Services",
				tunnel: "ssl", tlsCN: w.name + ".lumexa.lan", tlsSelf: true,
			})
			h.findings = append(h.findings, "rdp-nla-not-required", "tls-cert-self-signed")
		}
		if i%4 == 1 {
			h.findings = append(h.findings, "smb-signing-not-required")
		}
		out = append(out, h)
	}

	// Office printers and an old appliance.
	out = append(out,
		demoHost{net: 0, last: 51, hostname: "IMP-COMPTA", os: "HP FutureSmart", kind: model.AssetPrinter,
			mac: "3c:d9:2b:7a:10:4e", vendor: "Hewlett Packard",
			services: []demoService{
				{port: 80, proto: model.TCP, name: "http", product: "HP Embedded Web Server",
					title: "HP LaserJet MFP M528 - IMP-COMPTA", server: "HP-ChaiSOE/1.0", techs: []string{"HP EWS"}},
				{port: 443, proto: model.TCP, name: "http", product: "HP Embedded Web Server",
					tunnel: "ssl", tlsCN: "IMP-COMPTA", tlsSelf: true,
					title: "HP LaserJet MFP M528 - IMP-COMPTA", server: "HP-ChaiSOE/1.0"},
				{port: 515, proto: model.TCP, name: "printer"},
				{port: 9100, proto: model.TCP, name: "jetdirect"},
				{port: 161, proto: model.UDP, name: "snmp", product: "HP LaserJet", extra: "public"},
			},
			findings: []string{"snmp-default-community", "tls-cert-self-signed", "printer-unauth-admin"}},

		demoHost{net: 0, last: 52, hostname: "IMP-RDC", os: "Ricoh", kind: model.AssetPrinter,
			mac: "00:26:73:91:aa:0c", vendor: "Ricoh Company, Ltd.",
			services: []demoService{
				{port: 80, proto: model.TCP, name: "http", product: "Ricoh Web Image Monitor",
					title: "Web Image Monitor - MP C3004", server: "Web-Server/3.0"},
				{port: 9100, proto: model.TCP, name: "jetdirect"},
				{port: 161, proto: model.UDP, name: "snmp", product: "Ricoh MP C3004", extra: "public"},
			},
			findings: []string{"snmp-default-community"}},

		demoHost{net: 0, last: 60, hostname: "NAS-BUREAU", os: "Linux 4.4", kind: model.AssetStorage,
			mac: "00:11:32:5c:7d:21", vendor: "Synology Incorporated",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.2p1",
					banner: "SSH-2.0-OpenSSH_8.2p1", sshAlgos: true},
				{port: 139, proto: model.TCP, name: "netbios-ssn", product: "Samba smbd", version: "4.10.18"},
				{port: 445, proto: model.TCP, name: "microsoft-ds", product: "Samba smbd", version: "4.10.18"},
				{port: 5000, proto: model.TCP, name: "http", product: "Synology DiskStation Manager",
					title: "DiskStation - NAS-BUREAU", server: "nginx", techs: []string{"DSM", "nginx"}},
				{port: 2049, proto: model.TCP, name: "nfs", product: "Linux nfsd", version: "3-4"},
			},
			findings: []string{"smb-signing-not-required", "nfs-exports-world-readable", "ssh-weak-algorithms"}},
	)

	// ---- VLAN 20, servers ------------------------------------------------
	out = append(out,
		demoHost{net: 1, last: 10, hostname: "DC-01", os: "Windows Server 2022", kind: model.AssetDC,
			mac: "00:50:56:9a:3f:11", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 53, proto: model.TCP, name: "domain", product: "Microsoft DNS", version: "6.1.7601"},
				{port: 88, proto: model.TCP, name: "kerberos-sec", product: "Microsoft Windows Kerberos"},
				{port: 135, proto: model.TCP, name: "msrpc", product: "Microsoft Windows RPC"},
				{port: 389, proto: model.TCP, name: "ldap", product: "Microsoft Windows Active Directory LDAP",
					extra: "Domain: lumexa.lan"},
				{port: 445, proto: model.TCP, name: "microsoft-ds", product: "Windows SMB", version: "3.1.1"},
				{port: 464, proto: model.TCP, name: "kpasswd5"},
				{port: 636, proto: model.TCP, name: "ldapssl", tunnel: "ssl", tlsCN: "DC-01.lumexa.lan"},
				{port: 3268, proto: model.TCP, name: "globalcatLDAP"},
				{port: 3389, proto: model.TCP, name: "ms-wbt-server", product: "Microsoft Terminal Services",
					tunnel: "ssl", tlsCN: "DC-01.lumexa.lan"},
				{port: 5985, proto: model.TCP, name: "wsman", product: "Microsoft HTTPAPI httpd", version: "2.0",
					server: "Microsoft-HTTPAPI/2.0"},
				{port: 53, proto: model.UDP, name: "domain", product: "Microsoft DNS"},
				{port: 88, proto: model.UDP, name: "kerberos-sec"},
				{port: 389, proto: model.UDP, name: "ldap"},
			},
			findings: []string{"ldap-anonymous-bind", "smb-signing-not-required"}},

		demoHost{net: 1, last: 11, hostname: "DC-02", os: "Windows Server 2019", kind: model.AssetDC,
			mac: "00:50:56:9a:3f:12", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 88, proto: model.TCP, name: "kerberos-sec", product: "Microsoft Windows Kerberos"},
				{port: 135, proto: model.TCP, name: "msrpc", product: "Microsoft Windows RPC"},
				{port: 389, proto: model.TCP, name: "ldap", product: "Microsoft Windows Active Directory LDAP"},
				{port: 445, proto: model.TCP, name: "microsoft-ds", product: "Windows SMB", version: "3.1.1"},
				{port: 3389, proto: model.TCP, name: "ms-wbt-server", tunnel: "ssl", tlsCN: "DC-02.lumexa.lan"},
			},
			findings: []string{"smb-signing-not-required"}},

		demoHost{net: 1, last: 20, hostname: "SRV-FILES", os: "Windows Server 2019", kind: model.AssetServer,
			mac: "00:50:56:9a:40:07", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 135, proto: model.TCP, name: "msrpc"},
				{port: 445, proto: model.TCP, name: "microsoft-ds", product: "Windows SMB", version: "3.1.1"},
				{port: 3389, proto: model.TCP, name: "ms-wbt-server", tunnel: "ssl", tlsCN: "SRV-FILES.lumexa.lan"},
			},
			findings: []string{"smb-null-session", "smb-signing-not-required"}},

		demoHost{net: 1, last: 25, hostname: "SRV-INTRANET", os: "Debian 12", kind: model.AssetServer,
			mac: "00:50:56:9a:41:aa", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "9.2p1",
					extra: "Debian 2+deb12u3", banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", sshAlgos: true},
				{port: 80, proto: model.TCP, name: "http", product: "nginx", version: "1.22.1",
					title: "Intranet Lumexa", server: "nginx/1.22.1", techs: []string{"nginx", "PHP", "Bootstrap"}},
				{port: 443, proto: model.TCP, name: "http", product: "nginx", version: "1.22.1",
					tunnel: "ssl", tlsCN: "intranet.lumexa.lan",
					title: "Intranet Lumexa", server: "nginx/1.22.1", techs: []string{"nginx", "PHP"}},
				{port: 3306, proto: model.TCP, name: "mysql", product: "MariaDB", version: "10.11.6"},
			},
			findings: []string{"tls-weak-protocols"}},

		demoHost{net: 1, last: 30, hostname: "SRV-GITLAB", os: "Ubuntu 22.04", kind: model.AssetServer,
			mac: "00:50:56:9a:42:1b", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.9p1",
					banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", sshAlgos: true},
				{port: 80, proto: model.TCP, name: "http", product: "nginx",
					title: "GitLab", server: "nginx", techs: []string{"GitLab", "nginx"}},
				{port: 443, proto: model.TCP, name: "http", product: "nginx", tunnel: "ssl",
					tlsCN: "gitlab.lumexa.lan", title: "GitLab", server: "nginx", techs: []string{"GitLab"}},
				{port: 5432, proto: model.TCP, name: "postgresql", product: "PostgreSQL", version: "14.10"},
			}},

		demoHost{net: 1, last: 35, hostname: "SRV-MONITOR", os: "Debian 12", kind: model.AssetServer,
			mac: "00:50:56:9a:43:2c", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "9.2p1",
					banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2", sshAlgos: true},
				{port: 3000, proto: model.TCP, name: "http", product: "Grafana", version: "10.2.2",
					title: "Grafana", server: "Grafana", techs: []string{"Grafana"}},
				{port: 9090, proto: model.TCP, name: "http", product: "Prometheus",
					title: "Prometheus Time Series Collection", techs: []string{"Prometheus"}},
				{port: 9100, proto: model.TCP, name: "http", product: "Prometheus node exporter"},
			},
			findings: []string{"elasticsearch-no-auth"}},

		demoHost{net: 1, last: 40, hostname: "SRV-BACKUP", os: "Linux 5.15", kind: model.AssetServer,
			mac: "00:50:56:9a:44:3d", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.4p1",
					banner: "SSH-2.0-OpenSSH_8.4p1", sshAlgos: true},
				{port: 873, proto: model.TCP, name: "rsync", product: "rsyncd", version: "3.2.7"},
				{port: 111, proto: model.TCP, name: "rpcbind", version: "2-4"},
				{port: 2049, proto: model.TCP, name: "nfs", product: "Linux nfsd", version: "3-4"},
			},
			findings: []string{"rsync-modules", "nfs-exports-world-readable"}},

		demoHost{net: 1, last: 45, hostname: "SRV-REDIS", os: "Debian 12", kind: model.AssetServer,
			mac: "00:50:56:9a:45:4e", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "9.2p1",
					banner: "SSH-2.0-OpenSSH_9.2p1", sshAlgos: true},
				{port: 6379, proto: model.TCP, name: "redis", product: "Redis key-value store", version: "7.0.15"},
			},
			findings: []string{"redis-no-auth"}},

		demoHost{net: 1, last: 50, hostname: "ESXI-01", os: "VMware ESXi 7.0", kind: model.AssetHypervisor,
			mac: "ac:1f:6b:22:9c:01", vendor: "Super Micro Computer, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.8",
					extra: "VMware", banner: "SSH-2.0-OpenSSH_8.8 VMware", sshAlgos: true},
				{port: 80, proto: model.TCP, name: "http", product: "VMware ESXi httpd",
					title: "ID_EESX_Welcome", server: "VMware/7.0"},
				{port: 443, proto: model.TCP, name: "http", product: "VMware ESXi SOAP API", version: "7.0.3",
					tunnel: "ssl", tlsCN: "esxi-01.lumexa.lan", tlsSelf: true,
					title: "ESXi-01 - VMware ESXi", server: "VMware/7.0", techs: []string{"VMware ESXi"}},
				{port: 902, proto: model.TCP, name: "vmware-auth", product: "VMware Authentication Daemon",
					version: "1.10", banner: "220 VMware Authentication Daemon Version 1.10"},
			},
			findings: []string{"tls-cert-self-signed", "ssh-password-auth"}},

		demoHost{net: 1, last: 51, hostname: "ESXI-02", os: "VMware ESXi 7.0", kind: model.AssetHypervisor,
			mac: "ac:1f:6b:22:9c:02", vendor: "Super Micro Computer, Inc.",
			services: []demoService{
				{port: 443, proto: model.TCP, name: "http", product: "VMware ESXi SOAP API", version: "7.0.3",
					tunnel: "ssl", tlsCN: "esxi-02.lumexa.lan", tlsSelf: true,
					title: "ESXI-02 - VMware ESXi", server: "VMware/7.0"},
				{port: 902, proto: model.TCP, name: "vmware-auth", product: "VMware Authentication Daemon"},
			},
			findings: []string{"tls-cert-self-signed"}},
	)

	// ---- VLAN 30, telephony ----------------------------------------------
	out = append(out,
		demoHost{net: 2, last: 10, hostname: "PBX-01", os: "Linux 4.19", kind: model.AssetServer,
			mac: "00:0c:29:51:6a:7b", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "7.4",
					banner: "SSH-2.0-OpenSSH_7.4", sshAlgos: true},
				{port: 80, proto: model.TCP, name: "http", product: "Apache httpd", version: "2.4.6",
					title: "FreePBX Administration", server: "Apache/2.4.6", techs: []string{"FreePBX", "Apache", "PHP"}},
				{port: 5038, proto: model.TCP, name: "asterisk-ami", product: "Asterisk Call Manager", version: "5.0.2",
					banner: "Asterisk Call Manager/5.0.2"},
				{port: 5060, proto: model.UDP, name: "sip", product: "Asterisk PBX", version: "16.30.0"},
			},
			findings: []string{"ssh-weak-algorithms", "ssh-password-auth"}},
	)
	phones := []struct {
		last int
		name string
	}{
		{41, "SIP-ACCUEIL"}, {42, "SIP-COMPTA-01"}, {43, "SIP-COMPTA-02"},
		{44, "SIP-DIR-01"}, {45, "SIP-SALLE-B204"}, {46, "SIP-SUPPORT-01"},
	}
	// Not every handset answers to the same thing: a headline list that is the same row
	// seven times says nothing about the estate.
	phoneFindings := [][]string{
		{"http-default-credentials"},
		{"tls-cert-self-signed"},
		{"telnet-cleartext"},
		{"http-default-credentials"},
		{"tls-cert-self-signed"},
		{"ssh-password-auth"},
	}
	for i, p := range phones {
		out = append(out, demoHost{
			net: 2, last: p.last, hostname: p.name, os: "Yealink", kind: model.AssetPhone,
			mac: macFor("80:5e:c0", i), vendor: "Yealink(Xiamen) Network",
			services: []demoService{
				{port: 80, proto: model.TCP, name: "http", product: "Yealink IP Phone",
					title: "Yealink T46S", server: "Yealink Embedded Web Server"},
				{port: 5060, proto: model.UDP, name: "sip", product: "Yealink SIP-T46S", version: "66.86.0.15"},
			},
			findings: phoneFindings[i%len(phoneFindings)],
		})
	}

	// ---- VLAN 99, management ---------------------------------------------
	out = append(out,
		demoHost{net: 3, last: 10, hostname: "SW-CORE-01", os: "ArubaOS-CX 10.11", kind: model.AssetNetwork,
			mac: "94:f1:28:3a:10:00", vendor: "Hewlett Packard Enterprise",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.4",
					banner: "SSH-2.0-OpenSSH_8.4 ArubaOS-CX", sshAlgos: true},
				{port: 443, proto: model.TCP, name: "http", product: "Aruba Web UI", tunnel: "ssl",
					tlsCN: "SW-CORE-01", tlsSelf: true, title: "Aruba 6300M", server: "lighttpd"},
				{port: 161, proto: model.UDP, name: "snmp", product: "Aruba 6300M", extra: "public"},
			},
			findings: []string{"snmp-default-community", "tls-cert-self-signed"}},

		demoHost{net: 3, last: 11, hostname: "SW-ACC-B2-01", os: "Cisco IOS 15.2", kind: model.AssetNetwork,
			mac: "00:1b:0c:aa:11:02", vendor: "Cisco Systems, Inc",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "Cisco SSH", version: "1.25",
					banner: "SSH-2.0-Cisco-1.25", sshAlgos: true},
				{port: 23, proto: model.TCP, name: "telnet", product: "Cisco telnetd",
					banner: "User Access Verification"},
				{port: 161, proto: model.UDP, name: "snmp", product: "Cisco IOS 15.2(7)E3", extra: "public"},
			},
			findings: []string{"telnet-cleartext", "snmp-default-community"}},

		demoHost{net: 3, last: 12, hostname: "SW-ACC-RDC-02", os: "Cisco IOS 15.2", kind: model.AssetNetwork,
			mac: "00:1b:0c:aa:11:03", vendor: "Cisco Systems, Inc",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "Cisco SSH", version: "1.25",
					banner: "SSH-2.0-Cisco-1.25", sshAlgos: true},
				{port: 23, proto: model.TCP, name: "telnet", product: "Cisco telnetd"},
				{port: 161, proto: model.UDP, name: "snmp", product: "Cisco IOS 15.2(7)E3", extra: "public"},
			},
			findings: []string{"telnet-cleartext", "snmp-default-community"}},

		demoHost{net: 3, last: 20, hostname: "ILO-SRV-FILES", os: "HPE iLO 5", kind: model.AssetNetwork,
			mac: "48:df:37:12:ab:cd", vendor: "Hewlett Packard Enterprise",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "HPE iLO SSH", banner: "SSH-2.0-HPEiLO", sshAlgos: true},
				{port: 443, proto: model.TCP, name: "http", product: "HPE iLO 5 web interface", version: "2.78",
					tunnel: "ssl", tlsCN: "ILO-SRV-FILES", tlsSelf: true, tlsExp: true,
					title: "HPE iLO 5", server: "HPE-iLO-Server/1.30", techs: []string{"HPE iLO"}},
				{port: 17990, proto: model.TCP, name: "ilo-remote-console"},
			},
			findings: []string{"tls-cert-expired", "tls-cert-self-signed", "http-default-credentials"}},

		demoHost{net: 3, last: 21, hostname: "IDRAC-ESXI-01", os: "Dell iDRAC 9", kind: model.AssetNetwork,
			mac: "d0:94:66:33:cd:ef", vendor: "Dell Inc.",
			services: []demoService{
				{port: 443, proto: model.TCP, name: "http", product: "Dell iDRAC 9", version: "6.10",
					tunnel: "ssl", tlsCN: "IDRAC-ESXI-01", tlsSelf: true,
					title: "iDRAC9 - IDRAC-ESXI-01", server: "Mbedthis-Appweb"},
				{port: 623, proto: model.UDP, name: "asf-rmcp", product: "IPMI 2.0"},
			},
			findings: []string{"ipmi-cipher-zero", "tls-cert-self-signed"}},

		demoHost{net: 3, last: 30, hostname: "UPS-SALLE-TECH", os: "APC AOS", kind: model.AssetIoT,
			mac: "00:c0:b7:45:67:89", vendor: "American Power Conversion",
			services: []demoService{
				{port: 80, proto: model.TCP, name: "http", product: "APC AOS web interface",
					title: "APC | Log On", server: "APC AOS"},
				{port: 161, proto: model.UDP, name: "snmp", product: "APC Smart-UPS", extra: "public"},
			},
			findings: []string{"snmp-default-community", "snmp-write-community"}},
	)

	return out
}

func macFor(oui string, i int) string {
	return oui + ":" + hex2(i*7+3) + ":" + hex2(i*13+11) + ":" + hex2(i*29+5)
}

func hex2(v int) string {
	const digits = "0123456789abcdef"
	v &= 0xff
	return string([]byte{digits[v>>4], digits[v&0x0f]})
}

// placement says where a demo finding sits. Everything a reader actually looks at (the
// title, the severity, the description, the remediation) is taken from the real check
// catalogue instead, because a demo that writes its own wording drifts from the product,
// and the screenshots in the README would then show text NETY never produces. What is
// left here is only what the catalogue cannot know: which port the finding was raised on,
// and a plausible evidence line, since nothing was really probed.
type placement struct {
	port     int
	proto    model.Protocol
	evidence string
}

var placements = map[string]placement{
	"smb-signing-not-required":   {445, model.TCP, "SMB2 NEGOTIATE: signing enabled=true, signing required=false (dialect 0x0311)"},
	"smb-null-session":           {445, model.TCP, "anonymous SESSION_SETUP accepted, TREE_CONNECT \\\\IPC$ returned STATUS_SUCCESS"},
	"smb-anonymous-share-access": {445, model.TCP, "shares readable without credentials: SHARED, BACKUPS"},
	"rdp-nla-not-required":       {3389, model.TCP, "X.224 Connection Confirm: PROTOCOL_RDP accepted, NLA not enforced"},
	"ldap-anonymous-bind":        {389, model.TCP, "anonymous bind: result 0 (success), defaultNamingContext=DC=lumexa,DC=lan"},
	"ldap-signing-not-required":  {389, model.TCP, "bind accepted without signing or channel binding"},
	"redis-no-auth":              {6379, model.TCP, "PING -> +PONG; INFO server -> redis_version:7.0.15, executable:/usr/bin/redis-server"},
	"snmp-default-community":     {161, model.UDP, "GET sysDescr.0 with community=public returned a valid response"},
	"snmp-write-community":       {161, model.UDP, "community \"private\" answered GET sysDescr.0"},
	"telnet-cleartext":           {23, model.TCP, "banner received: User Access Verification"},
	"ssh-weak-algorithms":        {22, model.TCP, "kex: diffie-hellman-group14-sha1; mac: hmac-sha1"},
	"ssh-password-auth":          {22, model.TCP, "server offers: publickey, password"},
	"tls-cert-self-signed":       {443, model.TCP, "issuer == subject, chain length 1"},
	"tls-cert-expired":           {443, model.TCP, "notAfter passed 93 days ago"},
	"tls-weak-protocols":         {443, model.TCP, "TLS 1.0 and TLS 1.1 accepted"},
	"nfs-exports-world-readable": {2049, model.TCP, "MOUNT EXPORT: /srv/shared -> (everyone)"},
	"rsync-modules":              {873, model.TCP, "module list received: backups, vmdk, archives"},
	"elasticsearch-no-auth":      {9200, model.TCP, "GET /_cluster/health -> 200, status green, 148 indices"},
	"printer-unauth-admin":       {80, model.TCP, "GET /hp/device/set_config_networkprotocols.html -> 200 without authentication"},
	"http-default-credentials":   {443, model.TCP, "authenticated with the vendor account printed on the chassis label"},
	"ipmi-cipher-zero":           {623, model.UDP, "RAKP: session opened with cipher suite 0"},
	"ipmi-exposed":               {623, model.UDP, "ASF RMCP presence pong, IPMI 2.0"},
	"ftp-anonymous":              {21, model.TCP, "USER anonymous -> 230 Login successful"},
}

// catalogue is the product's own check list, loaded once.
var catalogue = func() map[string]engine.CheckInfo {
	m := map[string]engine.CheckInfo{}
	for _, c := range checks.New(nil).Catalog() {
		m[c.ID] = c
	}
	return m
}()

// findingFor builds a demo finding for a check id, refusing ids the product does not
// actually have. An invented check in a screenshot is a promise the tool cannot keep.
func findingFor(id, ip string) model.Finding {
	info, ok := catalogue[id]
	if !ok {
		panic("netydemo: no such check in the catalogue: " + id)
	}
	p, ok := placements[id]
	if !ok {
		panic("netydemo: no placement for check: " + id)
	}
	return model.Finding{
		IP: ip, Port: p.port, Protocol: p.proto, CheckID: id,
		Title: info.Title, Severity: info.Severity,
		Description: info.Description, Evidence: p.evidence,
		Remediation: info.Remediation, References: info.References,
	}
}
