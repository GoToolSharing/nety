package ntlm

import "fmt"

// ProductClass tells whether a Windows build identifies a client, a server or
// is ambiguous (the same build ships as both).
type ProductClass string

const (
	ClassClient  ProductClass = "client"
	ClassServer  ProductClass = "server"
	ClassEither  ProductClass = "either"
	ClassUnknown ProductClass = "unknown"
)

type winBuild struct {
	name  string
	class ProductClass
}

// Windows 10/11 / Server 2016+ share major.minor 10.0: the build number is the
// discriminant.
var win10Builds = map[uint16]winBuild{
	10240: {"Windows 10 1507", ClassClient},
	10586: {"Windows 10 1511", ClassClient},
	14393: {"Windows Server 2016 / 10 1607", ClassEither},
	15063: {"Windows 10 1703", ClassClient},
	16299: {"Windows 10 1709 / Server 1709", ClassEither},
	17134: {"Windows 10 1803 / Server 1803", ClassEither},
	17763: {"Windows Server 2019 / 10 1809", ClassEither},
	18362: {"Windows 10 1903 / Server 1903", ClassEither},
	18363: {"Windows 10 1909 / Server 1909", ClassEither},
	19041: {"Windows 10 2004 / Server 2004", ClassEither},
	19042: {"Windows 10 20H2 / Server 20H2", ClassEither},
	19043: {"Windows 10 21H1", ClassClient},
	19044: {"Windows 10 21H2", ClassClient},
	19045: {"Windows 10 22H2", ClassClient},
	20348: {"Windows Server 2022", ClassServer},
	22000: {"Windows 11 21H2", ClassClient},
	22621: {"Windows 11 22H2", ClassClient},
	22631: {"Windows 11 23H2", ClassClient},
	25398: {"Windows Server 23H2", ClassServer},
	26100: {"Windows Server 2025 / 11 24H2", ClassEither},
	26200: {"Windows 11 25H2", ClassClient},
}

// WindowsProduct maps an NTLM/SMB OS version to a marketing name and a class.
// Unknown builds still return a generic but useful name.
func WindowsProduct(major, minor uint8, build uint16) (string, ProductClass) {
	switch {
	case major == 5 && minor == 0:
		return "Windows 2000", ClassEither
	case major == 5 && minor == 1:
		return "Windows XP", ClassClient
	case major == 5 && minor == 2:
		return "Windows Server 2003 / XP x64", ClassEither
	case major == 6 && minor == 0:
		return "Windows Server 2008 / Vista", ClassEither
	case major == 6 && minor == 1:
		return "Windows Server 2008 R2 / 7", ClassEither
	case major == 6 && minor == 2:
		return "Windows Server 2012 / 8", ClassEither
	case major == 6 && minor == 3:
		return "Windows Server 2012 R2 / 8.1", ClassEither
	case major == 10 && minor == 0:
		if b, ok := win10Builds[build]; ok {
			return b.name, b.class
		}
		switch {
		case build > 26200:
			return fmt.Sprintf("Windows 11 / Server (build %d)", build), ClassEither
		case build > 22000:
			return fmt.Sprintf("Windows 11 (build %d)", build), ClassClient
		case build >= 10240:
			return fmt.Sprintf("Windows 10 / Server (build %d)", build), ClassEither
		}
		return fmt.Sprintf("Windows 10.0.%d", build), ClassUnknown
	case major == 0 && minor == 0 && build == 0:
		return "", ClassUnknown
	}
	return fmt.Sprintf("Windows %d.%d.%d", major, minor, build), ClassUnknown
}

// Product returns WindowsProduct for v.
func (v Version) Product() (string, ProductClass) {
	return WindowsProduct(v.Major, v.Minor, v.Build)
}
