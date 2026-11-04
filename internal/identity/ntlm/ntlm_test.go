package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func av(id uint16, s string) []byte {
	v := EncodeUTF16(s)
	b := make([]byte, 4+len(v))
	binary.LittleEndian.PutUint16(b, id)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(v)))
	copy(b[4:], v)
	return b
}

// buildChallenge builds a realistic CHALLENGE message as sent by Windows.
func buildChallenge(target string, ti []byte, ver *Version) []byte {
	tn := EncodeUTF16(target)
	b := make([]byte, 56)
	copy(b, Signature)
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint16(b[12:], uint16(len(tn)))
	binary.LittleEndian.PutUint16(b[14:], uint16(len(tn)))
	binary.LittleEndian.PutUint32(b[16:], 56)
	flags := FlagUnicode | FlagNTLM | FlagTargetInfo | FlagTargetTypeDomain | FlagExtendedSessionSecurity
	if ver != nil {
		flags |= FlagVersion
		b[48], b[49] = ver.Major, ver.Minor
		binary.LittleEndian.PutUint16(b[50:], ver.Build)
		b[55] = 15
	}
	binary.LittleEndian.PutUint32(b[20:], flags)
	copy(b[24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint16(b[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(b[44:], uint32(56+len(tn)))
	b = append(b, tn...)
	b = append(b, ti...)
	return b
}

func sampleTargetInfo() []byte {
	var ti []byte
	ti = append(ti, av(AvNbDomainName, "CORP")...)
	ti = append(ti, av(AvNbComputerName, "DC01")...)
	ti = append(ti, av(AvDNSDomainName, "corp.example.local")...)
	ti = append(ti, av(AvDNSComputerName, "DC01.corp.example.local")...)
	ti = append(ti, av(AvDNSTreeName, "example.local")...)
	ts := make([]byte, 12)
	binary.LittleEndian.PutUint16(ts, AvTimestamp)
	binary.LittleEndian.PutUint16(ts[2:], 8)
	binary.LittleEndian.PutUint64(ts[4:], TimeToFiletime(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)))
	ti = append(ti, ts...)
	ti = append(ti, 0, 0, 0, 0)
	return ti
}

func TestParseChallenge(t *testing.T) {
	msg := buildChallenge("CORP", sampleTargetInfo(), &Version{Major: 10, Minor: 0, Build: 17763})
	c, err := ParseChallenge(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.TargetName != "CORP" || c.NetBIOSComputer != "DC01" || c.NetBIOSDomain != "CORP" ||
		c.DNSComputer != "DC01.corp.example.local" || c.DNSDomain != "corp.example.local" || c.DNSTree != "example.local" {
		t.Fatalf("bad decode: %+v", c)
	}
	if c.Version == nil || c.Version.String() != "10.0.17763" {
		t.Fatalf("version: %+v", c.Version)
	}
	if name, cl := c.Version.Product(); name != "Windows Server 2019 / 10 1809" || cl != ClassEither {
		t.Fatalf("product %q %q", name, cl)
	}
	if !c.Timestamp.Equal(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("timestamp %v", c.Timestamp)
	}
	if c.ServerChallenge != [8]byte{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Fatal("challenge")
	}
}

func TestParseChallengeNoVersion(t *testing.T) {
	msg := buildChallenge("WG", sampleTargetInfo(), nil)
	c, err := ParseChallenge(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != nil {
		t.Fatal("unexpected version")
	}
}

func TestFindChallengeInSPNEGO(t *testing.T) {
	msg := buildChallenge("CORP", sampleTargetInfo(), &Version{Major: 6, Minor: 1, Build: 7601})
	wrapped := SPNEGOResponse(msg)
	// prefix with junk that contains a bogus signature
	junk := append([]byte("xxNTLMSSP\x00\x01\x00"), wrapped...)
	c, err := FindChallenge(junk)
	if err != nil {
		t.Fatal(err)
	}
	if c.NetBIOSComputer != "DC01" {
		t.Fatal(c.NetBIOSComputer)
	}
	if _, err := FindChallenge([]byte("nothing here")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseChallengeHostile(t *testing.T) {
	good := buildChallenge("CORP", sampleTargetInfo(), &Version{Major: 10, Build: 20348})
	// every truncation must not panic
	for i := 0; i <= len(good); i++ {
		_, _ = ParseChallenge(good[:i])
		_, _ = FindChallenge(good[:i])
	}
	// corrupt offsets / lengths
	for _, off := range []int{12, 14, 16, 40, 42, 44} {
		bad := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(bad[off:], 0xfffffff0)
		_, _ = ParseChallenge(bad)
	}
	// AV pair with oversize length
	bad := append([]byte(nil), good...)
	tiOff := int(binary.LittleEndian.Uint32(bad[44:]))
	binary.LittleEndian.PutUint16(bad[tiOff+2:], 0xffff)
	c, err := ParseChallenge(bad)
	if err != nil {
		t.Fatal(err)
	}
	if c.NetBIOSDomain != "" {
		t.Fatal("expected no AV decode")
	}
	// random fuzz
	seed := uint32(1)
	for n := 0; n < 2000; n++ {
		m := append([]byte(nil), good...)
		for k := 0; k < 4; k++ {
			seed = seed*1664525 + 1013904223
			m[int(seed)%len(m)] = byte(seed >> 8)
		}
		_, _ = ParseChallenge(m)
	}
	if _, err := ParseChallenge([]byte("NTLMSSP\x00\x01\x00\x00\x00" + string(make([]byte, 30)))); err == nil {
		t.Fatal("type 1 accepted")
	}
}

func TestNegotiateMessage(t *testing.T) {
	m := NegotiateMessage()
	if len(m) != 40 || !bytes.Equal(m[:8], Signature) || binary.LittleEndian.Uint32(m[8:]) != 1 {
		t.Fatalf("bad type1 %x", m)
	}
	if binary.LittleEndian.Uint32(m[12:]) != DefaultNegotiateFlags {
		t.Fatal("flags")
	}
	if len(NegotiateMessageFlags(FlagNTLM)) != 32 {
		t.Fatal("no version expected")
	}
}

// MS-NLMP 4.2.4 NTLMv2 test vectors.
func TestNTLMv2Vectors(t *testing.T) {
	key := NTOWFv2("User", "Password", "Domain")
	if hex.EncodeToString(key) != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTOWFv2 %x", key)
	}
	var ti []byte
	ti = append(ti, av(AvNbDomainName, "Domain")...)
	ti = append(ti, av(AvNbComputerName, "Server")...)
	ti = append(ti, 0, 0, 0, 0)
	ch := &Challenge{TargetInfo: ti, Flags: FlagTargetInfo}
	copy(ch.ServerChallenge[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	cc := [8]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	ch.RawTimestamp = make([]byte, 8)
	res, err := AuthenticateWith(ch, Credentials{User: "User", Password: "Password", Domain: "Domain"}, cc, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	msg := res.Message
	ntBuf, ok := secBuf(msg, 20)
	if !ok || len(ntBuf) < 16 {
		t.Fatal("nt buf")
	}
	if hex.EncodeToString(ntBuf[:16]) != "68cd0ab851e51c96aabc927bebef6a1c" {
		t.Fatalf("NTProofStr %x", ntBuf[:16])
	}
	if hex.EncodeToString(res.SessionKey) != "8de40ccadbc14a82f15cb0ad0de95ca3" {
		t.Fatalf("session key %x", res.SessionKey)
	}
	user, _ := secBuf(msg, 36)
	if DecodeUTF16(user) != "User" {
		t.Fatal("user")
	}
}

func TestAnonymousAuthenticate(t *testing.T) {
	m := AnonymousAuthenticate(&Challenge{Flags: FlagTargetInfo})
	if binary.LittleEndian.Uint32(m[8:]) != 3 {
		t.Fatal("type")
	}
	lm, _ := secBuf(m, 12)
	nt, _ := secBuf(m, 20)
	if len(lm) != 1 || len(nt) != 0 {
		t.Fatal("anon responses")
	}
	if binary.LittleEndian.Uint32(m[60:])&FlagAnonymous == 0 {
		t.Fatal("anon flag")
	}
}

func TestSPNEGORoundTrip(t *testing.T) {
	tok := bytes.Repeat([]byte{0x41}, 300)
	init := SPNEGOInit(tok)
	tag, val, rest, err := ReadTLV(init)
	if err != nil || tag != 0x60 || len(rest) != 0 {
		t.Fatal("outer")
	}
	if !bytes.Contains(val, tok) {
		t.Fatal("token missing")
	}
	if _, _, _, err := ReadTLV([]byte{0x30, 0x85, 1, 2, 3, 4, 5}); err == nil {
		t.Fatal("expected error")
	}
	if _, _, _, err := ReadTLV([]byte{0x30, 0x82, 0xff}); err == nil {
		t.Fatal("expected error")
	}
}

func TestWindowsProduct(t *testing.T) {
	cases := []struct {
		ma, mi uint8
		b      uint16
		want   string
		class  ProductClass
	}{
		{10, 0, 20348, "Windows Server 2022", ClassServer},
		{10, 0, 22631, "Windows 11 23H2", ClassClient},
		{6, 1, 7601, "Windows Server 2008 R2 / 7", ClassEither},
		{5, 1, 2600, "Windows XP", ClassClient},
		{10, 0, 23000, "Windows 11 (build 23000)", ClassClient},
		{0, 0, 0, "", ClassUnknown},
	}
	for _, c := range cases {
		n, cl := WindowsProduct(c.ma, c.mi, c.b)
		if n != c.want || cl != c.class {
			t.Errorf("%d.%d.%d => %q %q", c.ma, c.mi, c.b, n, cl)
		}
	}
}

func TestFiletime(t *testing.T) {
	now := time.Date(2025, 1, 2, 3, 4, 5, 600, time.UTC)
	if got := FiletimeToTime(TimeToFiletime(now)); !got.Equal(now.Truncate(100)) {
		t.Fatal(got)
	}
	if !FiletimeToTime(0).IsZero() || !FiletimeToTime(^uint64(0)).IsZero() {
		t.Fatal("expected zero")
	}
}
