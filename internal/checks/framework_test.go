package checks

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// withTestChecks replaces the registry for the duration of a test.
func withTestChecks(t *testing.T, cs ...*Check) {
	t.Helper()
	regMu.Lock()
	saved := registry
	registry = nil
	regMu.Unlock()
	for _, c := range cs {
		register(c)
	}
	t.Cleanup(func() {
		regMu.Lock()
		registry = saved
		regMu.Unlock()
	})
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFrameworkRun(t *testing.T) {
	var running, maxRunning int32
	slow := &Check{
		Info: engine.CheckInfo{ID: "test-slow", Title: "Slow", Severity: model.SevLow, Description: "d"},
		Applies: func(t *Target) bool { return t.Service.Port < 1000 },
		Run: func(ctx context.Context, t *Target) []model.Finding {
			n := atomic.AddInt32(&running, 1)
			for {
				m := atomic.LoadInt32(&maxRunning)
				if n <= m || atomic.CompareAndSwapInt32(&maxRunning, m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&running, -1)
			return []model.Finding{t.Finding("ev")}
		},
	}
	intrusive := &Check{
		Info:    engine.CheckInfo{ID: "test-intrusive", Title: "I", Severity: model.SevHigh, Intrusive: true},
		Applies: func(t *Target) bool { return true },
		Run:     func(ctx context.Context, t *Target) []model.Finding { return []model.Finding{t.Finding("creds")} },
	}
	panicky := &Check{
		Info:    engine.CheckInfo{ID: "test-panic", Title: "P", Severity: model.SevHigh},
		Applies: func(t *Target) bool { return true },
		Run:     func(ctx context.Context, t *Target) []model.Finding { panic("boom") },
	}
	hostLevel := &Check{
		Info:      engine.CheckInfo{ID: "test-host", Title: "H", Severity: model.SevInfo},
		HostLevel: true,
		Applies:   func(t *Target) bool { return t.HasPort(22, model.TCP) && !t.HasPort(4444, model.TCP) },
		Run: func(ctx context.Context, t *Target) []model.Finding {
			return []model.Finding{t.FindingOn(0, "", "host"), t.FindingOn(0, "", "host dup")}
		},
	}
	withTestChecks(t, slow, intrusive, panicky, hostLevel)

	var svcs []model.Service
	for p := 1; p <= 40; p++ {
		svcs = append(svcs, model.Service{IP: "10.0.0.1", Port: p, Protocol: model.TCP, State: model.PortOpen})
	}
	svcs = append(svcs, model.Service{IP: "10.0.0.1", Port: 23, Protocol: model.TCP, State: model.PortClosed})
	c := New(quietLogger())
	fs, err := c.Run(context.Background(), model.Host{IP: "10.0.0.1"}, svcs, engine.CheckOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.CheckID]++
		if f.IP != "10.0.0.1" || f.FirstSeen.IsZero() {
			t.Fatalf("bad finding %+v", f)
		}
	}
	if counts["test-slow"] != 40 || counts["test-intrusive"] != 0 || counts["test-panic"] != 0 || counts["test-host"] != 1 {
		t.Fatalf("counts %v", counts)
	}
	if maxRunning > MaxConcurrentPerHost || maxRunning < 2 {
		t.Fatalf("concurrency %d", maxRunning)
	}
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Port > fs[i].Port {
			t.Fatal("not sorted")
		}
	}
	fs, _ = c.Run(context.Background(), model.Host{IP: "10.0.0.1"}, svcs[:1], engine.CheckOptions{AllowDefaultCreds: true})
	got := false
	for _, f := range fs {
		got = got || f.CheckID == "test-intrusive"
	}
	if !got {
		t.Fatal("intrusive check not run when allowed")
	}
	if len(c.Catalog()) != 4 || c.Catalog()[0].ID != "test-host" {
		t.Fatalf("catalog %v", c.Catalog())
	}
}

func TestFrameworkCancel(t *testing.T) {
	block := &Check{
		Info:    engine.CheckInfo{ID: "test-block", Title: "B"},
		Applies: func(t *Target) bool { return true },
		Run: func(ctx context.Context, t *Target) []model.Finding {
			<-ctx.Done()
			return nil
		},
	}
	withTestChecks(t, block)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var svcs []model.Service
	for p := 1; p <= 20; p++ {
		svcs = append(svcs, model.Service{Port: p, Protocol: model.TCP})
	}
	start := time.Now()
	_, err := New(nil).Run(ctx, model.Host{IP: "10.0.0.2"}, svcs, engine.CheckOptions{})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("err=%v elapsed=%v", err, time.Since(start))
	}
	if _, err := New(nil).Run(context.Background(), model.Host{}, nil, engine.CheckOptions{}); err == nil {
		t.Fatal("expected error without IP")
	}
}

// TestCatalogIntegrity validates every registered check's metadata.
func TestCatalogIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range allChecks() {
		i := c.Info
		if i.ID == "" || i.Title == "" || i.Description == "" || i.Severity == "" || c.Run == nil {
			t.Errorf("incomplete check %+v", i)
		}
		if c.Applies == nil && !c.HostLevel {
			t.Errorf("%s: service check without Applies", i.ID)
		}
		if c.Remediation == "" {
			t.Errorf("%s: missing remediation", i.ID)
		}
		if seen[i.ID] {
			t.Errorf("duplicate %s", i.ID)
		}
		seen[i.ID] = true
	}
}

func TestPrintable(t *testing.T) {
	if got := printable([]byte("a\r\n\x00b"), 100); got != `a\r\n\x00b` {
		t.Fatal(got)
	}
	if got := printable([]byte("abcdef"), 3); got != "abc…" {
		t.Fatal(got)
	}
}
