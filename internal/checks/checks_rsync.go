package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/GoToolSharing/nety/internal/model"
)

func init() {
	register(&Check{
		Info: checkInfo("rsync-modules", "rsync daemon modules exposed", model.SevMedium,
			[]string{"rsync"},
			"The rsync daemon lists its modules to unauthenticated clients. Modules without 'auth users' can be read (and, when not read only, written) by anyone on the network; backups exposed this way frequently contain credentials."),
		Remediation: "Set 'list = no' on modules, protect every module with 'auth users' + 'secrets file', restrict 'hosts allow', and firewall port 873.",
		References:  []string{"https://download.samba.org/pub/rsync/rsyncd.conf.5"},
		Applies: func(t *Target) bool {
			return svcIs(t.Service, model.TCP, []string{"rsync"}, 873)
		},
		Run: runRsync,
	})
}

type rsyncModule struct {
	Name, Comment string
	Anonymous     bool
	Checked       bool
	Detail        string
}

// rsyncGreet performs the @RSYNCD version exchange and returns a reader.
func rsyncGreet(c net.Conn, t *Target) (*bufio.Reader, string, error) {
	r := bufio.NewReader(io.LimitReader(c, 256<<10))
	l, err := r.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, "@RSYNCD:") {
		return nil, "", fmt.Errorf("rsync: unexpected greeting %q", printable([]byte(l), 60))
	}
	ver := strings.Fields(strings.TrimPrefix(l, "@RSYNCD:"))
	v := "30.0"
	if len(ver) > 0 {
		v = ver[0]
	}
	refreshDeadline(c, t.Timeout)
	if _, err := io.WriteString(c, "@RSYNCD: "+v+"\n"); err != nil {
		return nil, "", err
	}
	return r, v, nil
}

// rsyncParseList parses module listing lines until @RSYNCD: EXIT.
func rsyncParseList(r *bufio.Reader) ([]rsyncModule, error) {
	var mods []rsyncModule
	for i := 0; i < 1000; i++ {
		l, err := r.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if strings.HasPrefix(l, "@RSYNCD: EXIT") {
			return mods, nil
		}
		if strings.HasPrefix(l, "@ERROR") {
			return mods, fmt.Errorf("rsync: %s", printable([]byte(l), 120))
		}
		if l != "" && !strings.HasPrefix(l, "@RSYNCD:") {
			name, comment, _ := strings.Cut(l, "\t")
			name = strings.TrimSpace(name)
			if name != "" {
				mods = append(mods, rsyncModule{Name: printable([]byte(name), 64), Comment: printable([]byte(strings.TrimSpace(comment)), 100)})
			}
		}
		if err != nil {
			if len(mods) > 0 {
				return mods, nil
			}
			return nil, err
		}
	}
	return mods, nil
}

func runRsync(ctx context.Context, t *Target) []model.Finding {
	c, err := t.Dial(ctx)
	if err != nil {
		return nil
	}
	r, ver, err := rsyncGreet(c, t)
	if err != nil {
		c.Close()
		return nil
	}
	_, _ = io.WriteString(c, "\n") // empty module name = list
	mods, err := rsyncParseList(r)
	c.Close()
	if err != nil || len(mods) == 0 {
		return nil
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Name < mods[j].Name })
	anon := 0
	for i := range mods {
		if i >= 5 || ctx.Err() != nil {
			break
		}
		mods[i].Checked = true
		mods[i].Anonymous, mods[i].Detail = rsyncProbeModule(ctx, t, mods[i].Name)
		if mods[i].Anonymous {
			anon++
		}
	}
	var lines []string
	for _, m := range mods {
		s := m.Name
		if m.Comment != "" {
			s += " (" + m.Comment + ")"
		}
		if m.Checked {
			if m.Anonymous {
				s += " -> anonymous access OK"
			} else if m.Detail != "" {
				s += " -> " + m.Detail
			}
		}
		lines = append(lines, s)
	}
	ev := fmt.Sprintf("rsync protocol %s, %d module(s) listed:\n%s", ver, len(mods), strings.Join(limitStrings(lines, 30), "\n"))
	f := t.Finding(ev)
	if anon > 0 {
		f.Severity = model.SevHigh
		f.Title = "rsync daemon modules accessible without authentication"
	}
	return []model.Finding{f}
}

// rsyncProbeModule asks for a module and reports whether the daemon grants access without
// authentication. No file is listed or transferred: the connection is closed right after
// the daemon's answer.
func rsyncProbeModule(ctx context.Context, t *Target, name string) (bool, string) {
	if strings.ContainsAny(name, "\n\r") {
		return false, ""
	}
	c, err := t.Dial(ctx)
	if err != nil {
		return false, ""
	}
	defer c.Close()
	r, _, err := rsyncGreet(c, t)
	if err != nil {
		return false, ""
	}
	if _, err := io.WriteString(c, name+"\n"); err != nil {
		return false, ""
	}
	for i := 0; i < 20; i++ {
		l, err := r.ReadString('\n')
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "@RSYNCD: OK"):
			return true, ""
		case strings.HasPrefix(l, "@RSYNCD: AUTHREQD"):
			return false, "authentication required"
		case strings.HasPrefix(l, "@ERROR"):
			return false, printable([]byte(l), 100)
		}
		if err != nil {
			return false, ""
		}
	}
	return false, ""
}
