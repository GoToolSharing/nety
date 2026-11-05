package fingerprint

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	sshMsgKexInit    = 20
	maxSSHPacket     = 256 << 10
	maxSSHIdentLines = 32
)

// kexInit is a parsed SSH_MSG_KEXINIT (RFC 4253 §7.1).
type kexInit struct {
	KexAlgos        []string
	HostKeyAlgos    []string
	CiphersC2S      []string
	CiphersS2C      []string
	MACsC2S         []string
	MACsS2C         []string
	CompressionC2S  []string
	CompressionS2C  []string
	LanguagesC2S    []string
	LanguagesS2C    []string
	FirstKexFollows bool
}

// readSSHIdent reads the server identification string, skipping the optional pre-banner
// lines allowed by RFC 4253 §4.2.
func readSSHIdent(r *bufio.Reader) (ident string, pre []string, err error) {
	for range maxSSHIdentLines {
		line, err := readLimitedLine(r, 1024)
		if err != nil {
			return "", pre, err
		}
		if strings.HasPrefix(line, "SSH-") {
			return line, pre, nil
		}
		pre = append(pre, line)
	}
	return "", pre, errors.New("ssh: no identification string")
}

func readLimitedLine(r *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for sb.Len() < limit {
		b, err := r.ReadByte()
		if err != nil {
			if sb.Len() > 0 && errors.Is(err, io.EOF) {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			return "", err
		}
		if b == '\n' {
			return strings.TrimRight(sb.String(), "\r"), nil
		}
		sb.WriteByte(b)
	}
	return sb.String(), nil
}

// readSSHPlainPacket reads one unencrypted binary packet and returns its payload.
func readSSHPlainPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 5 || n > maxSSHPacket {
		return nil, fmt.Errorf("ssh: invalid packet length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	pad := int(buf[0])
	if pad+1 > len(buf) {
		return nil, errors.New("ssh: invalid padding length")
	}
	return buf[1 : len(buf)-pad], nil
}

// parseKexInit decodes a KEXINIT payload (starting with the message number).
func parseKexInit(p []byte) (*kexInit, error) {
	if len(p) < 17 || p[0] != sshMsgKexInit {
		return nil, errors.New("ssh: not a KEXINIT message")
	}
	p = p[17:] // msg + 16 byte cookie
	k := &kexInit{}
	lists := []*[]string{
		&k.KexAlgos, &k.HostKeyAlgos, &k.CiphersC2S, &k.CiphersS2C, &k.MACsC2S,
		&k.MACsS2C, &k.CompressionC2S, &k.CompressionS2C, &k.LanguagesC2S, &k.LanguagesS2C,
	}
	for _, dst := range lists {
		if len(p) < 4 {
			return nil, errors.New("ssh: truncated KEXINIT")
		}
		n := binary.BigEndian.Uint32(p)
		p = p[4:]
		if uint64(n) > uint64(len(p)) {
			return nil, errors.New("ssh: truncated KEXINIT name-list")
		}
		if n > 0 {
			*dst = strings.Split(string(p[:n]), ",")
		}
		p = p[n:]
	}
	if len(p) >= 1 {
		k.FirstKexFollows = p[0] != 0
	}
	return k, nil
}

// buildKexInit builds a KEXINIT payload (used by tests).
func buildKexInit(k *kexInit) []byte {
	p := []byte{sshMsgKexInit}
	p = append(p, make([]byte, 16)...)
	for _, l := range [][]string{
		k.KexAlgos, k.HostKeyAlgos, k.CiphersC2S, k.CiphersS2C, k.MACsC2S,
		k.MACsS2C, k.CompressionC2S, k.CompressionS2C, k.LanguagesC2S, k.LanguagesS2C,
	} {
		s := strings.Join(l, ",")
		p = binary.BigEndian.AppendUint32(p, uint32(len(s)))
		p = append(p, s...)
	}
	if k.FirstKexFollows {
		p = append(p, 1)
	} else {
		p = append(p, 0)
	}
	return append(p, 0, 0, 0, 0)
}

// framePlainPacket wraps a payload into an unencrypted binary packet.
func framePlainPacket(payload []byte) []byte {
	pad := 8 - (len(payload)+5)%8
	if pad < 4 {
		pad += 8
	}
	n := len(payload) + pad + 1
	out := binary.BigEndian.AppendUint32(nil, uint32(n))
	out = append(out, byte(pad))
	out = append(out, payload...)
	return append(out, make([]byte, pad)...)
}
