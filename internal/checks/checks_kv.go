package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// ---------------------------------------------------------------------------
// redis-no-auth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("redis-no-auth", "Redis accessible without authentication", model.SevCritical,
			[]string{"redis"},
			"The Redis server executes commands without requiring a password. An attacker can read and modify every key and, through CONFIG SET / MODULE LOAD / replication abuse, frequently obtain code execution on the host."),
		Remediation: "Require authentication (requirepass or ACL users), enable protected-mode, bind Redis to localhost or a dedicated interface and firewall port 6379.",
		References:  []string{"https://redis.io/docs/latest/operate/oss_and_stack/management/security/"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"redis"}, 6379, 6380)
		},
		Run: runRedis,
	})
}

func runRedis(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if isTLS(t.Service) {
		c = svcTLSClient(c)
	}
	if _, err := c.Write([]byte("INFO server\r\n")); err != nil {
		return nil
	}
	info, err := redisReadReply(bufio.NewReader(io.LimitReader(c, 128<<10)))
	if err != nil {
		t.Log.Debug("redis read", "err", err)
		return nil
	}
	_, _ = c.Write([]byte("QUIT\r\n"))
	fields := redisParseInfo(info)
	if fields["redis_version"] == "" {
		return nil
	}
	ev := fmt.Sprintf("INFO server answered without AUTH: redis_version=%s", fields["redis_version"])
	for _, k := range []string{"redis_mode", "os", "executable", "config_file"} {
		if v := fields[k]; v != "" {
			ev += fmt.Sprintf(" %s=%s", k, v)
		}
	}
	return []model.Finding{t.Finding(ev)}
}

// redisReadReply reads a RESP reply to INFO. Errors (-NOAUTH, -DENIED...) are returned as
// errors.
func redisReadReply(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("redis: empty reply")
	}
	switch line[0] {
	case '-':
		return "", fmt.Errorf("redis: %s", printable([]byte(line), 200))
	case '+':
		return line[1:], nil
	case '$':
		var n int
		if _, err := fmt.Sscanf(line[1:], "%d", &n); err != nil || n < 0 || n > 1<<20 {
			return "", fmt.Errorf("redis: bad bulk length")
		}
		buf := make([]byte, n)
		got, err := io.ReadFull(r, buf)
		if err != nil && got == 0 {
			return "", err
		}
		return string(buf[:got]), nil
	case '=': // RESP3 verbatim string
		return line, nil
	}
	return "", fmt.Errorf("redis: unexpected reply %q", printable([]byte(line), 40))
}

func redisParseInfo(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			m[k] = v
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// memcached-open
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("memcached-open", "Memcached accessible without authentication", model.SevMedium,
			[]string{"memcached"},
			"The memcached server answers commands without authentication. Cached data (sessions, tokens, application objects) can be read or poisoned; when UDP is enabled it can also be abused for traffic amplification."),
		Remediation: "Bind memcached to localhost or a private interface (-l), disable UDP (-U 0), enable SASL authentication if remote access is required and firewall port 11211.",
		References:  []string{"https://github.com/memcached/memcached/wiki/SASLHowto", "https://www.cisa.gov/news-events/alerts/2018/02/27/udp-based-amplification-attacks"},
		Applies: func(t *Target) bool {
			s := t.Service
			if s.Protocol == model.UDP {
				return s.Port == 11211 || strings.EqualFold(s.Name, "memcached")
			}
			return svcIs(s, model.TCP, []string{"memcached", "memcache"}, 11211)
		},
		Run: runMemcached,
	})
}

func runMemcached(ctx context.Context, t *Target) []model.Finding {
	if t.Service.Protocol == model.UDP {
		return memcachedUDP(ctx, t)
	}
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write([]byte("stats\r\n")); err != nil {
		return nil
	}
	stats := memcachedReadStats(bufio.NewReader(io.LimitReader(c, 64<<10)))
	_, _ = c.Write([]byte("quit\r\n"))
	if stats["version"] == "" {
		return nil
	}
	return []model.Finding{t.Finding(memcachedEvidence("TCP", stats))}
}

func memcachedUDP(ctx context.Context, t *Target) []model.Finding {
	c, err := t.DialUDP(ctx, t.Service.Port)
	if err != nil {
		return nil
	}
	defer c.Close()
	// 8 byte UDP frame header: request id, seq, total datagrams, reserved.
	req := append([]byte{0x4e, 0x45, 0, 0, 0, 1, 0, 0}, []byte("stats\r\n")...)
	if _, err := c.Write(req); err != nil {
		return nil
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil || n <= 8 || buf[0] != 0x4e || buf[1] != 0x45 {
		return nil
	}
	stats := memcachedReadStats(bufio.NewReader(bytes.NewReader(buf[8:n])))
	if stats["version"] == "" {
		return nil
	}
	f := t.Finding(memcachedEvidence("UDP", stats) + fmt.Sprintf("\nUDP enabled: 15-byte request produced a %d-byte response (amplification vector)", n))
	f.Severity = model.SevHigh
	return []model.Finding{f}
}

func memcachedReadStats(r *bufio.Reader) map[string]string {
	m := map[string]string{}
	for i := 0; i < 512; i++ {
		l, err := r.ReadString('\n')
		l = strings.TrimSpace(l)
		if l == "END" || strings.HasPrefix(l, "ERROR") || strings.HasPrefix(l, "CLIENT_ERROR") || strings.HasPrefix(l, "SERVER_ERROR") {
			break
		}
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "STAT" {
			m[f[1]] = f[2]
		}
		if err != nil {
			break
		}
	}
	return m
}

func memcachedEvidence(proto string, st map[string]string) string {
	ev := fmt.Sprintf("%s 'stats' answered without authentication: version=%s", proto, st["version"])
	for _, k := range []string{"curr_items", "curr_connections", "uptime"} {
		if v := st[k]; v != "" {
			ev += fmt.Sprintf(" %s=%s", k, v)
		}
	}
	return ev
}

// ---------------------------------------------------------------------------
// zookeeper-no-auth
// ---------------------------------------------------------------------------

func init() {
	register(&Check{
		Info: checkInfo("zookeeper-no-auth", "ZooKeeper four-letter-word commands exposed", model.SevMedium,
			[]string{"zookeeper"},
			"The ZooKeeper server answers administrative four-letter-word commands without authentication, disclosing its configuration, environment and clients. ZooKeeper data nodes without ACLs are typically also readable."),
		Remediation: "Restrict 4lw.commands.whitelist to the strictly needed commands (e.g. 'srvr, ruok'), enable SASL authentication with ACLs on znodes and firewall port 2181.",
		References:  []string{"https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_4lw"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"zookeeper"}, 2181)
		},
		Run: runZookeeper,
	})
}

func runZookeeper(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	defer c.Close()
	if _, err := c.Write([]byte("envi")); err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(c, 32<<10))
	s := string(b)
	if !strings.Contains(s, "zookeeper.version=") {
		return nil
	}
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		for _, k := range []string{"zookeeper.version=", "host.name=", "os.name=", "user.name=", "java.version="} {
			if strings.HasPrefix(l, k) {
				keep = append(keep, l)
			}
		}
	}
	return []model.Finding{t.Finding("'envi' four-letter command answered without authentication: " + strings.Join(keep, "; "))}
}

// --------------------------------------------------------------------------- small
// shared helpers for line protocols
// ---------------------------------------------------------------------------

// beU32 is a bounds-checked big-endian uint32 read.
func beU32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return binary.BigEndian.Uint32(b[off:]), true
}

// refreshDeadline extends the deadline of c by the target timeout.
func refreshDeadline(c interface{ SetDeadline(time.Time) error }, d time.Duration) {
	_ = c.SetDeadline(time.Now().Add(d))
}

// svcTLSClient wraps c in a TLS client that does not verify the certificate.
func svcTLSClient(c net.Conn) net.Conn {
	return tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // scanning
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func timeNowPlus(d time.Duration) time.Time { return time.Now().Add(d) }
