package identity

import (
	"testing"

	"github.com/vaadata/nety/internal/model"
)

func svcs(ports ...int) []model.Service {
	var out []model.Service
	for _, p := range ports {
		out = append(out, svc(p, ""))
	}
	return out
}

func TestInferKind(t *testing.T) {
	sshSvc := model.Service{Port: 22, Protocol: model.TCP, State: model.PortOpen, Name: "ssh", SSH: &model.SSHInfo{Banner: "SSH-2.0-Cisco-1.25"}}
	tests := []struct {
		name   string
		svcs   []model.Service
		ev     []model.IdentityEvidence
		vendor string
		want   model.AssetKind
	}{
		{"domain controller", svcs(53, 88, 135, 389, 445, 636, 3268), nil, "", model.AssetDC},
		{"printer jetdirect", svcs(80, 443, 9100), nil, "", model.AssetPrinter},
		{"printer ipp only", svcs(631, 80), nil, "", model.AssetPrinter},
		{"printer by vendor", svcs(80), nil, "Brother Industries", model.AssetPrinter},
		{"cisco snmp sysdescr", svcs(22, 23), []model.IdentityEvidence{ev(model.EvSNMPSysName, "sw1", "snmp/161", 60, "sysdescr", "Cisco IOS Software, C2960 Software")}, "", model.AssetNetwork},
		{"cisco ssh banner", []model.Service{sshSvc}, nil, "", model.AssetNetwork},
		{"telnet ssh only", svcs(22, 23), nil, "", model.AssetNetwork},
		{"fortinet vendor", svcs(443, 22), nil, "Fortinet, Inc.", model.AssetNetwork},
		{"voip sip vendor", svcs(80, 5060), nil, "Yealink Network Technology", model.AssetPhone},
		{"voip sip only", svcs(5060), nil, "", model.AssetPhone},
		{"esxi", []model.Service{{Port: 443, Protocol: model.TCP, State: model.PortOpen, Product: "VMware ESXi SOAP API"}}, nil, "", model.AssetHypervisor},
		{"vmware 902", svcs(443, 902, 22), nil, "", model.AssetHypervisor},
		{"synology", []model.Service{{Port: 5000, Protocol: model.TCP, State: model.PortOpen, HTTP: &model.HTTPInfo{Title: "Synology DiskStation"}}}, nil, "", model.AssetStorage},
		{"iscsi", svcs(22, 3260), nil, "", model.AssetStorage},
		{"windows 10 workstation", svcs(135, 139, 445, 3389), []model.IdentityEvidence{ev(model.EvOSVersion, "10.0.19045", "smb-ntlm/445", 60, "os_name", "Windows 10 22H2")}, "", model.AssetWorkstation},
		{"windows server by os", svcs(135, 445, 3389), []model.IdentityEvidence{ev(model.EvOSVersion, "6.3.9600", "smb1/445", 60, "os_name", "Windows Server 2012 R2 Standard 9600")}, "", model.AssetServer},
		{"windows ambiguous with server ports", svcs(80, 135, 445, 1433, 3389), []model.IdentityEvidence{ev(model.EvOSVersion, "10.0.17763", "smb-ntlm/445", 60, "os_name", "Windows Server 2019 / 10 1809")}, "", model.AssetServer},
		{"windows ports only", svcs(135, 445), nil, "", model.AssetWorkstation},
		{"linux server", svcs(22, 80, 443), nil, "", model.AssetServer},
		{"ssh only", svcs(22), nil, "", model.AssetServer},
		{"camera", svcs(80, 554), nil, "Hangzhou Hikvision Digital Technology", model.AssetIoT},
		{"raspberry no ports", nil, nil, "Raspberry Pi Trading Ltd", model.AssetIoT},
		{"apple laptop", svcs(5900), nil, "Apple, Inc.", model.AssetWorkstation},
		{"unknown", nil, nil, "", model.AssetUnknown},
		{"closed ports ignored", []model.Service{{Port: 9100, Protocol: model.TCP, State: model.PortClosed}}, nil, "", model.AssetUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InferKind(tt.svcs, tt.ev, tt.vendor); got != tt.want {
				t.Fatalf("InferKind=%q want %q", got, tt.want)
			}
		})
	}
}
