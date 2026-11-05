package identity

import (
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

// kindFacts is a normalized view of what is known about a host, used by the kind
// inference rules.
type kindFacts struct {
	tcp, udp map[int]bool
	names    map[string]bool // lowercase service names
	corpus   string          // lowercase concatenation of products, banners, sysDescr, OS names
	osNames  string          // lowercase OS descriptions (NTLM os_name, SMB NativeOS)
	vendor   string          // lowercase vendor(s)
	nTCP     int
}

func (f *kindFacts) has(ports ...int) bool {
	for _, p := range ports {
		if f.tcp[p] {
			return true
		}
	}
	return false
}

func (f *kindFacts) hasAny(proto map[int]bool, ports ...int) bool {
	for _, p := range ports {
		if proto[p] {
			return true
		}
	}
	return false
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func buildFacts(services []model.Service, ev []model.IdentityEvidence, vendor string) *kindFacts {
	f := &kindFacts{tcp: map[int]bool{}, udp: map[int]bool{}, names: map[string]bool{}}
	var corpus, osn, vend strings.Builder
	vend.WriteString(strings.ToLower(vendor))
	for _, s := range services {
		if s.State != "" && s.State != model.PortOpen && s.State != model.PortOpenFiltered {
			continue
		}
		switch s.Protocol {
		case model.UDP:
			f.udp[s.Port] = true
		default:
			if !f.tcp[s.Port] {
				f.nTCP++
			}
			f.tcp[s.Port] = true
		}
		if s.Name != "" {
			f.names[strings.ToLower(s.Name)] = true
		}
		for _, v := range []string{s.Product, s.Version, s.ExtraInfo, s.OSType, s.Banner} {
			corpus.WriteString(strings.ToLower(v))
			corpus.WriteByte('\n')
		}
		if s.HTTP != nil {
			corpus.WriteString(strings.ToLower(s.HTTP.Title + "\n" + s.HTTP.Server + "\n"))
		}
		if s.SSH != nil {
			corpus.WriteString(strings.ToLower(s.SSH.Banner) + "\n")
		}
		if s.TLS != nil {
			corpus.WriteString(strings.ToLower(s.TLS.SubjectCN + "\n" + s.TLS.Issuer + "\n"))
		}
		if strings.TrimSpace(s.OSType) != "" {
			osn.WriteString(strings.ToLower(s.OSType) + "\n")
		}
	}
	for _, e := range ev {
		switch e.Kind {
		case model.EvVendor:
			vend.WriteString("\n" + strings.ToLower(e.Value))
		case model.EvOSVersion:
			osn.WriteString(strings.ToLower(e.Value) + "\n")
			osn.WriteString(strings.ToLower(e.Attributes["os_name"]) + "\n")
		}
		for _, k := range []string{"sysdescr", "sysobjectid", "os_name"} {
			if v := e.Attributes[k]; v != "" {
				corpus.WriteString(strings.ToLower(v) + "\n")
			}
		}
	}
	f.osNames = osn.String()
	f.vendor = vend.String()
	f.corpus = corpus.String() + f.osNames
	return f
}

// Ports that indicate the host offers services to others (server role).
var serverPorts = []int{21, 25, 53, 80, 88, 110, 143, 389, 443, 465, 587, 636, 993, 995, 1433, 1521,
	2049, 3268, 3306, 5432, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 11211, 27017}

var (
	netDeviceText = []string{"cisco ios", "ios-xe", "ios xe", "nx-os", "cisco nexus", "cisco adaptive security", "junos", "juniper",
		"procurve", "arubaos", "aruba ", "fortigate", "fortios", "fortinet", "mikrotik", "routeros", "edgeos", "edgeswitch",
		"ubiquiti", "unifi", "pan-os", "palo alto", "comware", "extremexos", "extreme networks", "huawei versatile routing",
		"brocade", "dell networking", "dell emc networking", "sonicwall", "cisco-", "watchguard", "zyxel", "netgear prosafe",
		"allied telesis", "checkpoint", "check point", "gaia"}
	netDeviceVendors = []string{"cisco", "juniper", "fortinet", "aruba", "mikrotik", "routerboard", "ubiquiti", "palo alto",
		"extreme networks", "brocade", "arista", "allied telesis", "sonicwall", "watchguard", "ruckus"}
	printerText = []string{"jetdirect", "laserjet", "officejet", "designjet", "printer", "brother", "lexmark", "xerox",
		"ricoh", "kyocera", "epson", "konica", "bizhub", "sharp mx", "zebra", "imagerunner", "canon ir", "workcentre", "pagewide"}
	printerVendors = []string{"brother", "lexmark", "xerox", "ricoh", "kyocera", "seiko epson", "epson", "konica", "zebra", "sharp", "oki data", "toshiba tec"}
	voipVendors    = []string{"polycom", "yealink", "avaya", "grandstream", "snom", "mitel", "aastra", "gigaset", "fanvil", "alcatel-lucent enterprise", "spectralink", "cisco spa"}
	voipText       = []string{"polycom", "yealink", "avaya", "grandstream", "snom", "mitel", "aastra", "cisco spa", "sip phone", "ip phone", "fanvil"}
	hyperText      = []string{"esxi", "vmware esx", "vcenter", "vsphere", "proxmox", "xenserver", "citrix hypervisor", "hyper-v server", "ovirt", "nutanix"}
	storageText    = []string{"synology", "qnap", "netapp", "data ontap", "isilon", "onefs", "truenas", "freenas", "readynas", "buffalo", "terastation", "nas4free", "openmediavault", "powerstore", "unity ", "equallogic", "storeonce", "nimble storage", "pure storage", "drobo", "asustor", "western digital my cloud"}
	storageVendors = []string{"synology", "qnap", "netapp", "buffalo", "asustor", "drobo", "pure storage", "nimble"}
	iotStrongVend  = []string{"espressif", "tuya", "hikvision", "dahua", "axis communications", "sonos", "shelly", "ring llc", "nest labs", "ezviz", "reolink", "hangzhou", "philips lighting", "signify", "ecobee", "wyze", "amcrest", "uniview", "mobotix", "vivotek", "hanwha"}
	iotWeakVend    = []string{"raspberry", "google", "amazon", "roku", "samsung", "lg electronics", "xiaomi", "tp-link", "texas instruments", "murata", "azurewave", "particle", "arduino", "seeed", "nintendo", "sony"}
	iotText        = []string{"hikvision", "dahua", "axis network camera", "axis communications", "ip camera", "network camera", "webcam", "dvr", "nvr", "sonos", "chromecast", "esp8266", "esp32", "tasmota", "shelly"}
	winClientText  = []string{"windows 10", "windows 11", "windows 7", "windows 8", "windows xp", "windows vista"}
)

// InferKind guesses the asset kind from open services, identity evidence and the MAC
// vendor. It is a pure, deterministic function.
func InferKind(services []model.Service, ev []model.IdentityEvidence, vendor string) model.AssetKind {
	f := buildFacts(services, ev, vendor)

	// Domain controller.
	if f.has(88) && f.has(389, 636, 3268) {
		return model.AssetDC
	}
	if f.names["kerberos-sec"] && f.names["ldap"] {
		return model.AssetDC
	}

	// Hypervisor.
	if containsAny(f.corpus, hyperText...) {
		return model.AssetHypervisor
	}
	if f.has(902) && f.has(443, 5989, 427) {
		return model.AssetHypervisor
	}
	if f.has(8006) && containsAny(f.corpus, "pve", "proxmox") {
		return model.AssetHypervisor
	}

	// Network device via explicit software strings (SNMP sysDescr, SSH banners).
	if containsAny(f.corpus, netDeviceText...) && !containsAny(f.osNames, "windows") {
		return model.AssetNetwork
	}

	// Printer.
	if f.has(9100) || containsAny(f.corpus, printerText...) || containsAny(f.vendor, printerVendors...) {
		return model.AssetPrinter
	}
	if f.has(631, 515) && !f.has(22, 445) {
		return model.AssetPrinter
	}

	// VoIP.
	sip := f.has(5060, 5061) || f.hasAny(f.udp, 5060, 5061) || f.names["sip"] || f.names["sip-tls"]
	if containsAny(f.vendor, voipVendors...) || containsAny(f.corpus, voipText...) {
		return model.AssetPhone
	}
	if sip && f.nTCP <= 4 && !f.has(445, 22, 3389) {
		return model.AssetPhone
	}

	// Storage.
	if containsAny(f.corpus, storageText...) || containsAny(f.vendor, storageVendors...) || f.has(3260) {
		return model.AssetStorage
	}

	// Network device by vendor or by "management only" port profile.
	if containsAny(f.vendor, netDeviceVendors...) && !f.has(445, 3389, 135) {
		return model.AssetNetwork
	}
	if f.has(23) && !f.has(445, 3389, 135, 139) {
		onlyMgmt := true
		for p := range f.tcp {
			switch p {
			case 22, 23, 80, 443, 830, 161:
			default:
				onlyMgmt = false
			}
		}
		if onlyMgmt {
			return model.AssetNetwork
		}
	}

	// Strong IoT vendors (cameras, smart devices) before generic server rule.
	if containsAny(f.vendor, iotStrongVend...) || containsAny(f.corpus, iotText...) {
		return model.AssetIoT
	}

	windows := strings.Contains(f.osNames, "windows") || (f.has(445, 135, 139, 3389) && !f.has(22))
	hasServerPorts := f.has(serverPorts...)
	if windows {
		clientOS := containsAny(f.osNames, winClientText...)
		serverOS := strings.Contains(f.osNames, "server")
		ambiguous := strings.Contains(f.osNames, " / ")
		switch {
		case serverOS && !ambiguous:
			return model.AssetServer
		case hasServerPorts:
			return model.AssetServer
		case clientOS || ambiguous || f.has(445, 3389, 135, 139):
			return model.AssetWorkstation
		}
	}

	// Apple desktops/laptops.
	if strings.Contains(f.vendor, "apple") && !hasServerPorts {
		if strings.Contains(f.corpus, "mac os") || strings.Contains(f.corpus, "macos") || f.has(22, 5900, 88) || len(f.tcp) == 0 {
			return model.AssetWorkstation
		}
	}

	if hasServerPorts || f.has(22) {
		return model.AssetServer
	}

	if containsAny(f.vendor, iotWeakVend...) {
		return model.AssetIoT
	}
	return model.AssetUnknown
}
