package main

import "github.com/GoToolSharing/nety/internal/model"

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
			findings: []string{"snmp-default-community", "tls-cert-self-signed", "printer-unauthenticated-admin"}},

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
			findings: []string{"smb-signing-not-required", "nfs-world-readable-export", "ssh-weak-algorithms"}},
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
			findings: []string{"tls-certificate-expiring"}},

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
			findings: []string{"prometheus-unauthenticated"}},

		demoHost{net: 1, last: 40, hostname: "SRV-BACKUP", os: "Linux 5.15", kind: model.AssetServer,
			mac: "00:50:56:9a:44:3d", vendor: "VMware, Inc.",
			services: []demoService{
				{port: 22, proto: model.TCP, name: "ssh", product: "OpenSSH", version: "8.4p1",
					banner: "SSH-2.0-OpenSSH_8.4p1", sshAlgos: true},
				{port: 873, proto: model.TCP, name: "rsync", product: "rsyncd", version: "3.2.7"},
				{port: 111, proto: model.TCP, name: "rpcbind", version: "2-4"},
				{port: 2049, proto: model.TCP, name: "nfs", product: "Linux nfsd", version: "3-4"},
			},
			findings: []string{"rsync-module-listing", "nfs-world-readable-export"}},

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
			findings: []string{"tls-cert-self-signed", "esxi-ssh-enabled"}},

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
			findings: []string{"ssh-weak-algorithms", "asterisk-ami-exposed"}},
	)
	phones := []struct {
		last int
		name string
	}{
		{41, "SIP-ACCUEIL"}, {42, "SIP-COMPTA-01"}, {43, "SIP-COMPTA-02"},
		{44, "SIP-DIR-01"}, {45, "SIP-SALLE-B204"}, {46, "SIP-SUPPORT-01"},
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
			findings: []string{"voip-phone-default-web-credentials"},
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
			findings: []string{"tls-certificate-expired", "tls-cert-self-signed", "ilo-default-credentials"}},

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
			findings: []string{"snmp-default-community", "apc-default-credentials"}},
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

// findingFor returns the finding body for a check id, with the port it applies
// to. The texts are the ones a report would carry.
func findingFor(id, ip string) model.Finding {
	type def struct {
		title, desc, ev, fix string
		sev                  model.Severity
		port                 int
		proto                model.Protocol
		refs                 []string
	}
	defs := map[string]def{
		"smb-signing-not-required": {
			title: "Signature SMB non requise", sev: model.SevMedium, port: 445, proto: model.TCP,
			desc: "Le serveur accepte des sessions SMB non signées. Un attaquant en position d'homme du milieu peut relayer une authentification vers ce service.",
			ev:   "SMB2 NEGOTIATE: signing enabled=true, signing required=false (dialect 0x0311)",
			fix:  "Activer « Serveur réseau Microsoft : signer numériquement les communications (toujours) » par GPO sur l'ensemble du parc.",
			refs: []string{"https://learn.microsoft.com/windows-server/security/smb-signing"}},
		"smb-null-session": {
			title: "Session SMB anonyme acceptée", sev: model.SevHigh, port: 445, proto: model.TCP,
			desc: "Une session SMB sans authentification est acceptée et permet d'énumérer les partages.",
			ev:   "SESSION_SETUP anonyme accepté - TREE_CONNECT \\\\IPC$ : STATUS_SUCCESS",
			fix:  "Positionner RestrictAnonymous=1 et RestrictAnonymousSAM=1, et retirer « Tout le monde » des autorisations de partage."},
		"rdp-nla-not-required": {
			title: "RDP sans authentification réseau (NLA)", sev: model.SevMedium, port: 3389, proto: model.TCP,
			desc: "Le service RDP accepte les connexions sans NLA, ce qui expose la pile RDP avant toute authentification.",
			ev:   "X.224 Connection Confirm : PROTOCOL_RDP accepté (NLA non imposé)",
			fix:  "Exiger l'authentification au niveau du réseau dans les paramètres Bureau à distance ou par GPO."},
		"ldap-anonymous-bind": {
			title: "Bind LDAP anonyme autorisé", sev: model.SevMedium, port: 389, proto: model.TCP,
			desc: "Le contrôleur de domaine autorise un bind anonyme, permettant de lire le rootDSE et une partie de l'annuaire.",
			ev:   "bind anonyme : résultat 0 (success) - defaultNamingContext=DC=lumexa,DC=lan",
			fix:  "Positionner dsHeuristics pour interdire les binds anonymes."},
		"redis-no-auth": {
			title: "Redis accessible sans authentification", sev: model.SevCritical, port: 6379, proto: model.TCP,
			desc: "L'instance Redis répond aux commandes sans mot de passe. Toute machine pouvant l'atteindre peut lire et écrire l'intégralité des données, et souvent obtenir une exécution de commandes.",
			ev:   "PING → +PONG ; INFO server → redis_version:7.0.15, executable:/usr/bin/redis-server",
			fix:  "Définir requirepass, écouter uniquement sur l'interface nécessaire et filtrer l'accès au port."},
		"snmp-default-community": {
			title: "Communauté SNMP par défaut", sev: model.SevMedium, port: 161, proto: model.UDP,
			desc: "L'équipement répond à la communauté « public », divulguant sa configuration et son inventaire.",
			ev:   "GET sysDescr.0 avec community=public → réponse valide",
			fix:  "Remplacer les communautés par défaut, ou migrer vers SNMPv3 avec authentification et chiffrement."},
		"telnet-cleartext": {
			title: "Telnet exposé", sev: model.SevHigh, port: 23, proto: model.TCP,
			desc: "L'administration par Telnet est accessible : identifiants et session transitent en clair sur le réseau.",
			ev:   "220 bannière reçue - « User Access Verification »",
			fix:  "Désactiver Telnet (transport input ssh) et n'autoriser que SSH depuis le VLAN d'administration."},
		"ssh-weak-algorithms": {
			title: "Algorithmes SSH obsolètes proposés", sev: model.SevLow, port: 22, proto: model.TCP,
			desc: "Le serveur propose des algorithmes d'échange de clés ou de MAC considérés comme faibles.",
			ev:   "kex: diffie-hellman-group14-sha1 ; mac: hmac-sha1",
			fix:  "Restreindre KexAlgorithms et MACs aux suites modernes dans sshd_config."},
		"tls-cert-self-signed": {
			title: "Certificat TLS auto-signé", sev: model.SevInfo, port: 443, proto: model.TCP,
			desc: "Le service présente un certificat auto-signé : l'identité du serveur ne peut pas être vérifiée, ce qui banalise les avertissements du navigateur.",
			ev:   "issuer == subject, chaîne de longueur 1",
			fix:  "Émettre le certificat depuis l'autorité interne et le déployer."},
		"tls-certificate-expired": {
			title: "Certificat TLS expiré", sev: model.SevMedium, port: 443, proto: model.TCP,
			desc: "Le certificat présenté a expiré.",
			ev:   "notAfter dépassé de 93 jours",
			fix:  "Renouveler le certificat et mettre en place une surveillance des échéances."},
		"tls-certificate-expiring": {
			title: "Certificat TLS proche de l'expiration", sev: model.SevLow, port: 443, proto: model.TCP,
			desc: "Le certificat expire dans moins de 60 jours.",
			ev:   "notAfter dans 40 jours",
			fix:  "Planifier le renouvellement."},
		"nfs-world-readable-export": {
			title: "Export NFS accessible à tous", sev: model.SevHigh, port: 2049, proto: model.TCP,
			desc: "Un export NFS est proposé sans restriction d'hôte.",
			ev:   "MOUNT EXPORT : /srv/partage → (everyone)",
			fix:  "Restreindre chaque export aux hôtes légitimes dans /etc/exports et recharger le serveur."},
		"rsync-module-listing": {
			title: "Modules rsync énumérables sans authentification", sev: model.SevMedium, port: 873, proto: model.TCP,
			desc: "Le démon rsync liste ses modules sans authentification.",
			ev:   "liste reçue : backups, vmdk, archives",
			fix:  "Activer auth users / secrets file et filtrer l'accès au port."},
		"prometheus-unauthenticated": {
			title: "Prometheus accessible sans authentification", sev: model.SevMedium, port: 9090, proto: model.TCP,
			desc: "L'interface Prometheus est accessible librement et divulgue l'inventaire supervisé ainsi que les cibles internes.",
			ev:   "GET /api/v1/targets → 200, 148 cibles listées",
			fix:  "Placer le service derrière un reverse proxy authentifié et le restreindre au VLAN d'administration."},
		"asterisk-ami-exposed": {
			title: "Interface d'administration Asterisk exposée", sev: model.SevHigh, port: 5038, proto: model.TCP,
			desc: "Le port AMI d'Asterisk est joignable depuis le réseau utilisateur. Il permet, avec des identifiants, de piloter l'ensemble de la téléphonie.",
			ev:   "bannière : Asterisk Call Manager/5.0.2",
			fix:  "Limiter permit/deny dans manager.conf au seul serveur applicatif et filtrer le port."},
		"ilo-default-credentials": {
			title: "Identifiants par défaut sur iLO", sev: model.SevCritical, port: 443, proto: model.TCP,
			desc: "L'interface d'administration matérielle accepte un compte par défaut, donnant un contrôle complet du serveur, console comprise.",
			ev:   "authentification réussie avec le compte d'usine imprimé sur l'étiquette du châssis",
			fix:  "Changer le mot de passe d'administration, créer des comptes nominatifs et isoler iLO dans le VLAN d'administration."},
		"apc-default-credentials": {
			title: "Identifiants par défaut sur l'onduleur", sev: model.SevHigh, port: 80, proto: model.TCP,
			desc: "La carte réseau de l'onduleur accepte le compte constructeur par défaut, permettant d'éteindre les équipements alimentés.",
			ev:   "authentification réussie avec le compte apc/apc",
			fix:  "Changer le mot de passe et restreindre l'accès à l'interface."},
		"voip-phone-default-web-credentials": {
			title: "Interface du téléphone en identifiants par défaut", sev: model.SevMedium, port: 80, proto: model.TCP,
			desc: "L'interface web du poste accepte le compte administrateur par défaut, donnant accès à la configuration SIP et aux identifiants du compte.",
			ev:   "authentification réussie avec le compte admin par défaut",
			fix:  "Déployer un mot de passe d'administration par provisioning et désactiver l'interface web si elle n'est pas utilisée."},
		"printer-unauthenticated-admin": {
			title: "Administration de l'imprimante sans authentification", sev: model.SevMedium, port: 80, proto: model.TCP,
			desc: "Le serveur web embarqué expose les pages d'administration sans authentification : carnet d'adresses, configuration SMTP et LDAP compris.",
			ev:   "GET /hp/device/set_config_networkprotocols.html → 200 sans authentification",
			fix:  "Définir un mot de passe administrateur sur l'équipement et restreindre son administration au VLAN dédié."},
		"ipmi-cipher-zero": {
			title: "IPMI : cipher suite 0 acceptée", sev: model.SevCritical, port: 623, proto: model.UDP,
			desc: "Le BMC accepte la suite de chiffrement 0, qui autorise une session authentifiée sans vérifier le mot de passe.",
			ev:   "RAKP : ouverture de session acceptée avec cipher suite 0",
			fix:  "Désactiver la cipher suite 0 sur le BMC et isoler l'interface d'administration."},
		"esxi-ssh-enabled": {
			title: "SSH actif en permanence sur l'hyperviseur", sev: model.SevLow, port: 22, proto: model.TCP,
			desc: "Le service SSH de l'hyperviseur est démarré en permanence, contrairement à la configuration recommandée.",
			ev:   "SSH-2.0-OpenSSH_8.8 VMware",
			fix:  "Arrêter le service SSH et ne l'activer qu'au besoin, depuis le VLAN d'administration."},
	}
	d, ok := defs[id]
	if !ok {
		d = def{title: id, sev: model.SevInfo, port: 0, proto: model.TCP}
	}
	return model.Finding{
		IP: ip, Port: d.port, Protocol: d.proto, CheckID: id, Title: d.title,
		Severity: d.sev, Description: d.desc, Evidence: d.ev, Remediation: d.fix,
		References: d.refs,
	}
}
