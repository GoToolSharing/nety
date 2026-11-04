// Command nety is the NETY server: an internal-network mapping and VLAN
// segmentation testing platform.
//
//	nety serve                 start the web platform
//	nety user add <name>       create an account
//	nety user list             list accounts
//	nety user passwd <name>    reset a password
//	nety version               print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GoToolSharing/nety/internal/api"
	"github.com/GoToolSharing/nety/internal/auth"
	"github.com/GoToolSharing/nety/internal/bus"
	"github.com/GoToolSharing/nety/internal/checks"
	"github.com/GoToolSharing/nety/internal/config"
	"github.com/GoToolSharing/nety/internal/discovery"
	"github.com/GoToolSharing/nety/internal/export"
	"github.com/GoToolSharing/nety/internal/fingerprint"
	"github.com/GoToolSharing/nety/internal/identity"
	"github.com/GoToolSharing/nety/internal/jobs"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/netif"
	"github.com/GoToolSharing/nety/internal/portscan"
	"github.com/GoToolSharing/nety/internal/rawnet"
	"github.com/GoToolSharing/nety/internal/segment"
	"github.com/GoToolSharing/nety/internal/server"
	"github.com/GoToolSharing/nety/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nety: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no command given")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "user":
		return cmdUser(args[1:])
	case "version", "--version", "-v":
		fmt.Println(config.VersionString())
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `NETY - internal network mapping and VLAN segmentation testing

Usage:
  nety serve [flags]            start the web platform
  nety user add <username>      create an account
  nety user list                list accounts
  nety user passwd <username>   reset a password
  nety version                  print the version

Run "nety serve -h" for the server flags. Every flag also has a NETY_*
environment variable (see docs/).
`)
}

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

func bindFlags(fs *flag.FlagSet, cfg *config.Config) {
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "data directory (database, TLS material)")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "TLS certificate (default: self-signed, generated)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "TLS private key")
	fs.BoolVar(&cfg.TLSDisabled, "no-tls", cfg.TLSDisabled, "serve plain HTTP (only behind a trusted proxy)")
	fs.BoolVar(&cfg.TrustedProxy, "trusted-proxy", cfg.TrustedProxy, "honour X-Forwarded-For")
	fs.StringVar(&cfg.BootstrapAdmin, "admin", cfg.BootstrapAdmin, "username created on first start")
	fs.StringVar(&cfg.BootstrapPass, "admin-password", cfg.BootstrapPass, "password for it (default: generated and printed once)")
	fs.IntVar(&cfg.MaxConcurrentScans, "max-scans", cfg.MaxConcurrentScans, "scans running at the same time")
	fs.IntVar(&cfg.DefaultRate, "rate", cfg.DefaultRate, "default packets per second")
	fs.IntVar(&cfg.MaxRate, "max-rate", cfg.MaxRate, "hard packet-rate ceiling")
	fs.IntVar(&cfg.WorkerCount, "workers", cfg.WorkerCount, "service-detection workers per scan")
	fs.StringVar(&cfg.NmapProbesPath, "nmap-probes", cfg.NmapProbesPath, "path to nmap-service-probes (optional, improves version detection)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug|info|warn|error")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "text|json")
	fs.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "log file (default: stderr)")
}

func loadConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	cfg := config.Default()
	if err := cfg.ApplyEnv(); err != nil {
		return cfg, err
	}
	bindFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if err := cfg.Normalize(); err != nil {
		return cfg, err
	}
	return cfg, cfg.EnsureDirs()
}

func newLogger(cfg config.Config) (*slog.Logger, func(), error) {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	out := os.Stderr
	closer := func() {}
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		out = f
		closer = func() { f.Close() }
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(out, opts)
	} else {
		h = slog.NewTextHandler(out, opts)
	}
	log := slog.New(h)
	slog.SetDefault(log)
	return log, closer, nil
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	log, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()

	log.Info("starting NETY", "version", config.Version, "commit", config.Commit, "data", cfg.DataDir)

	st, err := store.Open(cfg.DBPath(), log)
	if err != nil {
		return err
	}
	defer st.Close()

	authSvc := auth.New(st, auth.Config{
		SessionTTL:     cfg.SessionTTL,
		SessionIdleTTL: cfg.SessionIdleTTL,
		MaxAttempts:    cfg.MaxLoginAttempt,
		LockoutWindow:  cfg.LockoutWindow,
	})
	if err := bootstrapAdmin(context.Background(), st, authSvc, cfg, log); err != nil {
		return err
	}

	// The fingerprinter uses nmap's probe database when the operator has it
	// installed; detection degrades gracefully without it.
	if cfg.NmapProbesPath != "" {
		fingerprint.SetProbesPath(cfg.NmapProbesPath)
		log.Info("using nmap service probes", "path", cfg.NmapProbesPath)
	}

	eventBus := bus.New()
	defer eventBus.Close()

	engines := buildEngines(log)
	raw := rawnet.CanRaw()
	if !raw {
		log.Warn("raw sockets are not available: SYN scanning, ARP discovery and the layer-2 " +
			"techniques are disabled. Run as root or grant CAP_NET_RAW and CAP_NET_ADMIN.")
	}

	runner := jobs.New(st, eventBus, engines, jobs.Options{
		MaxConcurrentScans: cfg.MaxConcurrentScans,
		DefaultRate:        cfg.DefaultRate,
		MaxRate:            cfg.MaxRate,
		DefaultTimeout:     cfg.DefaultTimeout,
		Workers:            cfg.WorkerCount,
	}, log)
	defer runner.Close()

	// A scan that was running when the process died is returned to the queue
	// and marked resumable rather than silently lost.
	if err := runner.Recover(context.Background()); err != nil {
		log.Error("cannot recover interrupted scans", "error", err)
	}

	apiHandler := api.New(api.Deps{
		Store:      st,
		Auth:       authSvc,
		Bus:        eventBus,
		Runner:     runner,
		Engines:    engines,
		Exporter:   export.New(),
		Config:     cfg,
		Log:        log,
		Started:    time.Now(),
		RawCapable: raw,
	})

	srv, err := server.New(cfg, apiHandler.Handler(), log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go housekeeping(ctx, authSvc, log)

	if err := srv.ListenAndServe(ctx); err != nil {
		return err
	}
	log.Info("pausing running scans before exit")
	runner.Close()
	// Process-wide safety net: the segmentation engine already reverts its own
	// changes per test, but a crash-stop must never leave a sub-interface or a
	// route behind on the operator's machine.
	if err := netif.RestoreAll(); err != nil {
		log.Error("could not revert every network change; check your interfaces and routes", "error", err)
	}
	log.Info("goodbye")
	return nil
}

// buildEngines wires the scanning implementations. Engines unavailable on this
// platform are left nil; the runner skips their phases and the API reports it.
func buildEngines(log *slog.Logger) jobs.Engines {
	return jobs.Engines{
		Discoverer:    discovery.New(log),
		PortScanner:   portscan.New(log),
		Fingerprinter: fingerprint.New(log),
		Identity:      identity.NewCollector(log),
		Correlator:    identity.NewCorrelator(),
		Checker:       checks.New(log),
		NetInspector:  netif.New(log),
		Segment:       segment.New(log, portscan.New(log), netif.New(log)),
	}
}

// housekeeping purges expired sessions periodically.
func housekeeping(ctx context.Context, authSvc *auth.Service, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := authSvc.PurgeExpired(ctx); err != nil {
				log.Warn("session purge failed", "error", err)
			} else if n > 0 {
				log.Debug("purged expired sessions", "count", n)
			}
		}
	}
}

// bootstrapAdmin creates the first account on an empty database and prints the
// generated password once, so the operator can log in immediately.
func bootstrapAdmin(ctx context.Context, st *store.Store, authSvc *auth.Service, cfg config.Config, log *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	username := cfg.BootstrapAdmin
	if username == "" {
		username = "admin"
	}
	password := cfg.BootstrapPass
	generated := false
	if password == "" {
		password, err = auth.GeneratePassword()
		if err != nil {
			return err
		}
		generated = true
	}
	if err := auth.ValidatePassword(password); err != nil {
		return fmt.Errorf("bootstrap password: %w", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, model.User{
		Username: username, DisplayName: "Administrator", Role: model.RoleAdmin,
		PasswordHash: hash, MustChangePW: generated,
	}); err != nil {
		return fmt.Errorf("create the first account: %w", err)
	}
	if generated {
		fmt.Fprintf(os.Stderr, "\n"+strings.Repeat("─", 64)+"\n"+
			"  First start: an administrator account has been created.\n\n"+
			"    username: %s\n    password: %s\n\n"+
			"  This password is shown once and must be changed at first login.\n"+
			strings.Repeat("─", 64)+"\n\n", username, password)
	}
	log.Info("created the first administrator account", "username", username)
	return nil
}

// ---------------------------------------------------------------------------
// user management
// ---------------------------------------------------------------------------

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nety user <add|list|passwd> ...")
	}
	sub := args[0]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	role := fs.String("role", "operator", "admin|operator|viewer")
	password := fs.String("password", "", "password (default: generated and printed)")
	display := fs.String("name", "", "display name")

	cfg, err := loadConfig(fs, args[1:])
	if err != nil {
		return err
	}
	log, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()

	st, err := store.Open(cfg.DBPath(), log)
	if err != nil {
		return err
	}
	defer st.Close()

	authSvc := auth.New(st, auth.Config{SessionTTL: cfg.SessionTTL})
	ctx := context.Background()
	rest := fs.Args()

	switch sub {
	case "list":
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-20s %-10s %-24s %s\n", "USERNAME", "ROLE", "DISPLAY NAME", "STATUS")
		for _, u := range users {
			status := "active"
			if u.Disabled {
				status = "disabled"
			} else if u.MustChangePW {
				status = "must change password"
			}
			fmt.Printf("%-20s %-10s %-24s %s\n", u.Username, u.Role, u.DisplayName, status)
		}
		return nil

	case "add":
		if len(rest) != 1 {
			return errors.New("usage: nety user add <username> [-role ...] [-password ...]")
		}
		r := model.Role(*role)
		if !auth.ValidRole(r) {
			return fmt.Errorf("unknown role %q", *role)
		}
		pw := *password
		generated := false
		if pw == "" {
			if pw, err = auth.GeneratePassword(); err != nil {
				return err
			}
			generated = true
		}
		if err := auth.ValidatePassword(pw); err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		u, err := st.CreateUser(ctx, model.User{
			Username: rest[0], DisplayName: *display, Role: r,
			PasswordHash: hash, MustChangePW: true,
		})
		if err != nil {
			return err
		}
		fmt.Printf("created %s (%s)\n", u.Username, u.Role)
		if generated {
			fmt.Printf("password: %s\n", pw)
		}
		return nil

	case "passwd":
		if len(rest) != 1 {
			return errors.New("usage: nety user passwd <username> [-password ...]")
		}
		u, err := st.UserByName(ctx, rest[0])
		if err != nil {
			return err
		}
		pw := *password
		generated := false
		if pw == "" {
			if pw, err = auth.GeneratePassword(); err != nil {
				return err
			}
			generated = true
		}
		if err := authSvc.SetPassword(ctx, u.ID, pw, true); err != nil {
			return err
		}
		fmt.Printf("password reset for %s\n", u.Username)
		if generated {
			fmt.Printf("password: %s\n", pw)
		}
		return nil

	default:
		return fmt.Errorf("unknown user subcommand %q", sub)
	}
}
